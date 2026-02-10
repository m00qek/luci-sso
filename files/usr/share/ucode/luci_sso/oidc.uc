import * as uclient from 'uclient';
import * as lucihttp from 'lucihttp';
import * as crypto from 'luci_sso.crypto';

// --- Internal Helpers ---

/**
 * Decodes JSON safely and logs errors.
 * @private
 */
function safe_json_parse(io, data) {
	let raw = data;
	if (type(data) == "object" && type(data.read) == "function") {
		raw = data.read();
	}

	if (type(raw) != "string") return null;

	try {
		return json(raw);
	} catch (e) {
		if (io) {
			io.log("warn", `JSON parse error: ${e} (Data: ${substr(raw, 0, 64)}...)`);
		}
		return null;
	}
}

/**
 * Generates a unique cache path for an identifier (issuer or JWKS URI).
 * @private
 */
function get_cache_path(id, prefix) {
	let h = crypto.b64url_encode(crypto.sha256(id));
	return `/var/run/luci-sso/oidc-${prefix}-${substr(h, 0, 32)}.json`;
}

/**
 * Reads and validates a cached object.
 * @private
 */
function _read_cache(io, path, ttl) {
	try {
		let content = io.read_file(path);
		if (!content) return null;

		let data = safe_json_parse(io, content);
		if (!data || !data.cached_at) return null;

		if ((io.time() - data.cached_at) > ttl) return null;

		return data;
	} catch (e) {
		return null;
	}
}

/**
 * Writes data to cache with a timestamp.
 * @private
 */
function _write_cache(io, path, data) {
	try {
		let cache_data = { ...data, cached_at: io.time() };
		io.write_file(path, sprintf("%J", cache_data));
	} catch (e) {}
}

/**
 * Checks if a URL uses HTTPS.
 * @private
 */
function _is_https(url) {
	return (type(url) == "string" && substr(url, 0, 8) == "https://");
}

// --- Public API ---

/**
 * Fetches and caches OIDC discovery document.
 */
export function discover(io, issuer, options) {
	if (type(issuer) != "string") die("CONTRACT_VIOLATION: issuer must be a string");

	if (!_is_https(issuer)) return { ok: false, error: "INSECURE_ISSUER_URL" };

	options = options || {};
	let cache_path = options.cache_path || get_cache_path(issuer, "discovery");
	let ttl = options.ttl || 3600;

	let cached = _read_cache(io, cache_path, ttl);
	if (cached && cached.issuer == issuer) {
		return { ok: true, data: cached };
	}

	// The fetch URL might be different from the logical issuer URL (Split-Horizon)
	let fetch_url = options.internal_issuer_url || issuer;
	if (!_is_https(fetch_url)) return { ok: false, error: "INSECURE_FETCH_URL" };

	if (substr(fetch_url, -1) != '/') fetch_url += '/';
	fetch_url += ".well-known/openid-configuration";

	let response = io.http_get(fetch_url, { verify: true });
	let issuer_id = crypto.safe_id(issuer);

	if (!response || response.error) {
		io.log("warn", `Discovery fetch failed for [id: ${issuer_id}]: ${response?.error || "no response"}`);
		return { ok: false, error: "NETWORK_ERROR" };
	}
	if (response.status != 200) {
		io.log("warn", `Discovery fetch HTTP ${response.status} from [id: ${issuer_id}]`);
		return { ok: false, error: "DISCOVERY_FAILED", details: response.status };
	}

	let config = safe_json_parse(io, response.body);
	if (!config) {
		io.log("error", `Invalid discovery document format from [id: ${issuer_id}]`);
		return { ok: false, error: "INVALID_DISCOVERY_DOC" };
	}

	// 2.1 Issuer Validation: The document MUST claim to be the issuer we requested
	if (!config.issuer) {
		io.log("error", `Discovery document missing issuer field from [id: ${issuer_id}]`);
		return { ok: false, error: "DISCOVERY_MISSING_ISSUER" };
	}
	if (config.issuer && config.issuer != issuer) {
		io.log("error", `Discovery issuer mismatch: Requested [id: ${issuer_id}], got [id: ${crypto.safe_id(config.issuer)}]`);
		return { ok: false, error: "DISCOVERY_ISSUER_MISMATCH", 
			 details: `Requested ${issuer}, got ${config.issuer}` };
	}

	io.log("info", `Discovery successful for [id: ${issuer_id}]`);

	let required = ["authorization_endpoint", "token_endpoint", "jwks_uri"];
	for (let i, field in required) {
		if (type(config[field]) != "string" || length(config[field]) == 0) {
			return { ok: false, error: "MISSING_REQUIRED_FIELD", details: field };
		}
		if (!_is_https(config[field])) {
			return { ok: false, error: "INSECURE_ENDPOINT", details: field };
		}
	}

	// OPTIONAL: RP-Initiated Logout support (RFC 7522 / OIDC)
	if (config.end_session_endpoint && !_is_https(config.end_session_endpoint)) {
		io.log("warn", `Insecure end_session_endpoint ignored from [id: ${issuer_id}]`);
		delete config.end_session_endpoint;
	}

	_write_cache(io, cache_path, config);

	return { ok: true, data: config };
};

/**
 * Fetches JWK Set from IdP with caching.
 */
export function fetch_jwks(io, jwks_uri, options) {
	if (type(jwks_uri) != "string") die("CONTRACT_VIOLATION: jwks_uri must be a string");

	if (!_is_https(jwks_uri)) return { ok: false, error: "INSECURE_JWKS_URI" };

	options = options || {};
	let cache_path = options.cache_path || get_cache_path(jwks_uri, "jwks");
	let ttl = options.ttl || 86400; // 24 hours default
	let uri_id = crypto.safe_id(jwks_uri);

	if (!options.force) {
		let cached = _read_cache(io, cache_path, ttl);
		if (cached && type(cached.keys) == "array") {
			io.log("info", `JWKS loaded from cache for [id: ${uri_id}]`);
			return { ok: true, data: cached.keys };
		}
	}

	let response = io.http_get(jwks_uri, { verify: true });
	if (!response || response.error) {
		io.log("warn", `JWKS fetch failed for [id: ${uri_id}]: ${response?.error || "no response"}`);
		return { ok: false, error: "NETWORK_ERROR" };
	}
	if (response.status != 200) {
		io.log("warn", `JWKS fetch HTTP ${response.status} from [id: ${uri_id}]`);
		return { ok: false, error: "JWKS_FETCH_FAILED", details: response.status };
	}

	let jwks = safe_json_parse(io, response.body);
	if (!jwks || type(jwks.keys) != "array") {
		io.log("error", `Invalid JWKS format from [id: ${uri_id}]`);
		return { ok: false, error: "INVALID_JWKS_FORMAT" };
	}

	io.log("info", `JWKS successfully fetched: ${length(jwks.keys)} keys from [id: ${uri_id}]`);

	_write_cache(io, cache_path, jwks);

	return { ok: true, data: jwks.keys };
};

/**
 * Finds the correct JWK by key ID (kid).
 */
export function find_jwk(keys, kid) {
	if (type(keys) != "array") die("CONTRACT_VIOLATION: keys must be an array");
	if (!kid) {
		if (length(keys) > 0) return { ok: true, data: keys[0] };
		return { ok: false, error: "NO_KEYS_AVAILABLE" };
	}
	for (let i, key in keys) {
		if (key.kid == kid) return { ok: true, data: key };
	}
	return { ok: false, error: "KEY_NOT_FOUND", details: kid };
};

/**
 * Generates the authorization URL.
 */
export function get_auth_url(io, config, discovery, params) {
	let query = {
		response_type: "code",
		client_id: config.client_id,
		redirect_uri: config.redirect_uri,
		scope: config.scope || "openid profile email",
		state: params.state,
		nonce: params.nonce,
		code_challenge: params.code_challenge,
		code_challenge_method: "S256"
	};

	let url = discovery.authorization_endpoint;
	let sep = (index(url, '?') == -1) ? '?' : '&';
	for (let k, v in query) {
		if (v == null) continue;
		url += `${sep}${k}=${lucihttp.urlencode(v, 1)}`;
		sep = '&';
	}
	return url;
};

/**
 * Exchanges authorization code for tokens.
 */
export function exchange_code(io, config, discovery, code, verifier, session_id) {
	if (!_is_https(discovery.token_endpoint)) return { ok: false, error: "INSECURE_TOKEN_ENDPOINT" };

	// Audit logging for PKCE usage (Blocker #2)
	let sid_ctx = session_id ? ` [session_id: ${session_id}]` : "";
	io.log("info", `Initiating token exchange${sid_ctx} with PKCE verifier (len: ${length(verifier)})`);

	if (type(verifier) != "string" || length(verifier) < 43) {
		io.log("error", `Rejected token exchange${sid_ctx}: PKCE verifier too short`);
		return { ok: false, error: "INVALID_PKCE_VERIFIER" };
	}

	let body = {
		grant_type: "authorization_code",
		client_id: config.client_id,
		client_secret: config.client_secret,
		redirect_uri: config.redirect_uri,
		code: code,
		code_verifier: verifier
	};

	let encoded_body = "";
	let sep = "";
	for (let k, v in body) {
		if (v == null) continue;
		encoded_body += `${sep}${k}=${lucihttp.urlencode(v, 1)}`;
		sep = "&";
	}

	let response = io.http_post(discovery.token_endpoint, {
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: encoded_body,
		verify: true // Explicitly request TLS certificate verification
	});

	if (!response || response.error) {
		io.log("warn", `Token exchange network error${sid_ctx}: ${response?.error || "no response"}`);
		return { ok: false, error: "NETWORK_ERROR" };
	}
	if (response.status != 200) {
		let err_data = safe_json_parse(io, response.body);
		if (err_data && err_data.error == "invalid_grant") {
			io.log("error", `Token exchange failed (invalid_grant)${sid_ctx}`);
			return { ok: false, error: "OIDC_INVALID_GRANT" };
		}
		io.log("warn", `Token exchange HTTP ${response.status}${sid_ctx}`);
		return { ok: false, error: "TOKEN_EXCHANGE_FAILED", details: response.status };
	}

	let tokens = safe_json_parse(io, response.body);
	if (!tokens) {
		io.log("error", `Invalid JSON response in token exchange${sid_ctx}`);
		return { ok: false, error: "INVALID_JSON" };
	}

	io.log("info", `Token exchange successful${sid_ctx}`);

	return { ok: true, data: tokens };
};

/**
 * Verifies ID Token and matches nonce.
 * 
 * @param {object} [io] - Optional I/O provider for logging
 * @param {object} tokens - Token response {id_token, access_token}
 * @param {array} keys - JWK keyset
 * @param {object} config - UCI configuration
 * @param {object} handshake - Handshake state {nonce, ...}
 * @param {object} discovery - Discovery document
 * @param {number} now - Current timestamp
 * @param {object} [policy] - Security policy (Second Dimension) {allowed_algs}
 */
export function verify_id_token(io, tokens, keys, config, handshake, discovery, now, policy) {
	// Support both (io, tokens, ...) and (tokens, keys, ...) for backward compatibility
	let provider = io;
	let t = tokens;
	let k = keys;
	let c = config;
	let h = handshake;
	let d = discovery;
	let n = now;
	let p_arg = policy;

	if (type(io) == "object" && !io.log) {
		// First arg is tokens
		provider = null;
		t = io;
		k = tokens;
		c = keys;
		h = config;
		d = handshake;
		n = discovery;
		p_arg = now;
	}

	if (!t.id_token) return { ok: false, error: "MISSING_ID_TOKEN" };

	// 1. Policy Enforcement (Second Dimension)
	// Hardcoded safe defaults for production.
	const DEFAULT_POLICY = { allowed_algs: ["RS256", "ES256"] };
	let p = p_arg || DEFAULT_POLICY;

	let parts = split(t.id_token, ".");
	let header = safe_json_parse(provider, crypto.b64url_decode(parts[0]));
	if (!header) return { ok: false, error: "INVALID_JWT_HEADER" };

	// BLOCKER: Enforce algorithm whitelist from policy
	let alg_allowed = false;
	for (let a in p.allowed_algs) {
		if (header.alg == a) {
			alg_allowed = true;
			break;
		}
	}
	if (!alg_allowed) {
		return { ok: false, error: "UNSUPPORTED_ALGORITHM", details: header.alg };
	}

	let jwk_res = find_jwk(k, header.kid);
	if (!jwk_res.ok) return jwk_res;

	let pem_res = crypto.jwk_to_pem(jwk_res.data);
	if (!pem_res.ok) return pem_res;

	// MANDATORY Claims Check: 
	// The issuer in the token MUST match the discovery document, 
	// AND the discovery document MUST match our configured expectation.
	if (d.issuer != c.issuer_url) {
		return { ok: false, error: "DISCOVERY_ISSUER_MISMATCH", details: `Expected ${c.issuer_url}, IdP claimed ${d.issuer}` };
	}

	let validation_opts = { 
		alg: header.alg,
		now: n,
		clock_tolerance: c.clock_tolerance,
		iss: c.issuer_url,
		aud: c.client_id
	};

	let result = crypto.verify_jwt(t.id_token, pem_res.data, validation_opts);
	if (!result.ok) return result;

	let payload = result.data;

	// 3. OIDC Mandatory Claims Check
	if (!payload.sub) {
		return { ok: false, error: "MISSING_SUB_CLAIM" };
	}

	// 3.1 Nonce Check (Blocker #3: Mandatory)
	if (!h.nonce || !payload.nonce) {
		return { ok: false, error: "MISSING_NONCE" };
	}
	if (payload.nonce != h.nonce) {
		return { ok: false, error: "NONCE_MISMATCH" };
	}

	// 3.2 Authorized Party Check (Blocker #5 in 1770661209: Universal AZP)
	// If the azp claim is present, it MUST match our client_id to prevent Confused Deputy attacks.
	if (payload.azp && payload.azp !== c.client_id) {
		return { ok: false, error: "AZP_MISMATCH" };
	}

	// 3.3 Access Token Hash Check (Blocker #7 in 1770661270: Binding)
	// Per OIDC Core 3.1.3.3: If at_hash is present, it MUST match the access_token.
	// PARANOID MODE: We enforce that both MUST be present to ensure cryptographic binding.
	if (!t.access_token) {
		return { ok: false, error: "MISSING_ACCESS_TOKEN" };
	}
	if (!payload.at_hash) {
		return { ok: false, error: "MISSING_AT_HASH" };
	}

	let full_hash = crypto.sha256(t.access_token);
	if (!full_hash) return { ok: false, error: "CRYPTO_ERROR" };

	// OIDC Core 1.0 Section 3.1.3.6: at_hash is the left-most half 
	// of the hash of the octets of the ASCII representation of the access_token.
	// We MUST extract the first 16 bytes manually to ensure byte-safety 
	// (ucode substr() counts characters, which is incorrect for raw bytes).
	let left_half = "";
	for (let i = 0; i < 16; i++) {
		left_half += chr(ord(full_hash, i));
	}
	let expected_hash = crypto.b64url_encode(left_half);

	if (expected_hash != payload.at_hash) {
		return { ok: false, error: "AT_HASH_MISMATCH" };
	}

	let user_data = {
		sub: payload.sub,
		email: payload.email || payload.sub,
		name: payload.name
	};

	return { ok: true, data: user_data };
};
