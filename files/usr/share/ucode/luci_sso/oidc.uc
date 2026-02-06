import * as uclient from 'uclient';
import * as lucihttp from 'lucihttp';
import * as crypto from 'luci_sso.crypto';

// --- Internal Helpers ---

/**
 * Validates the IO object.
 * @private
 */
function validate_io(io) {
	if (type(io) != "object" || type(io.http_get) != "function" || type(io.time) != "function") {
		die("CONTRACT_VIOLATION: Invalid IO provider");
	}
}

/**
 * Decodes JSON safely.
 * @private
 */
function safe_json_parse(data) {
	let raw = data;
	if (type(data) == "object" && type(data.read) == "function") {
		raw = data.read();
	}
	
	if (type(raw) != "string") return null;

	try {
		return json(raw);
	} catch (e) {
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

		let data = safe_json_parse(content);
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
		data.cached_at = io.time();
		io.write_file(path, sprintf("%J", data));
	} catch (e) {}
}

// --- Public API ---

/**
 * Fetches and caches OIDC discovery document.
 */
export function discover(io, issuer, options) {
	validate_io(io);
	if (type(issuer) != "string") die("CONTRACT_VIOLATION: issuer must be a string");

	options = options || {};
	let cache_path = options.cache_path || get_cache_path(issuer, "discovery");
	let ttl = options.ttl || 3600;
	
	let cached = _read_cache(io, cache_path, ttl);
	if (cached && cached.issuer == issuer) {
		return { ok: true, data: cached };
	}
	
	let discovery_url = issuer;
	if (substr(discovery_url, -1) != '/') discovery_url += '/';
	discovery_url += ".well-known/openid-configuration";
	
	let response = io.http_get(discovery_url);
	if (!response || response.error) return { ok: false, error: "NETWORK_ERROR" };
	if (response.status != 200) return { ok: false, error: "DISCOVERY_FAILED", details: response.status };
	
	let config = safe_json_parse(response.body);
	if (!config) return { ok: false, error: "INVALID_JSON" };

	let required = ["authorization_endpoint", "token_endpoint", "jwks_uri"];
	for (let i, field in required) {
		if (type(config[field]) != "string" || length(config[field]) == 0) {
			return { ok: false, error: "MISSING_REQUIRED_FIELD", details: field };
		}
	}
	
	_write_cache(io, cache_path, config);
	
	return { ok: true, data: config };
};

/**
 * Fetches JWK Set from IdP with caching.
 */
export function fetch_jwks(io, jwks_uri, options) {
	validate_io(io);
	if (type(jwks_uri) != "string") die("CONTRACT_VIOLATION: jwks_uri must be a string");

	options = options || {};
	let cache_path = options.cache_path || get_cache_path(jwks_uri, "jwks");
	let ttl = options.ttl || 86400; // 24 hours default
	
	let cached = _read_cache(io, cache_path, ttl);
	if (cached && type(cached.keys) == "array") {
		return { ok: true, data: cached.keys };
	}

	let response = io.http_get(jwks_uri);
	if (!response || response.error) return { ok: false, error: "NETWORK_ERROR" };
	if (response.status != 200) return { ok: false, error: "JWKS_FETCH_FAILED", details: response.status };
	
	let jwks = safe_json_parse(response.body);
	if (!jwks || type(jwks.keys) != "array") return { ok: false, error: "INVALID_JWKS_FORMAT" };
	
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
		url += `${sep}${k}=${lucihttp.urlencode(v)}`;
		sep = '&';
	}
	return url;
};

/**
 * Exchanges authorization code for tokens.
 */
export function exchange_code(io, config, discovery, code, verifier) {
	validate_io(io);
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
		encoded_body += `${sep}${k}=${lucihttp.urlencode(v)}`;
		sep = "&";
	}

	let response = io.http_post(discovery.token_endpoint, {
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: encoded_body
	});

	if (!response || response.error) return { ok: false, error: "NETWORK_ERROR" };
	if (response.status != 200) return { ok: false, error: "TOKEN_EXCHANGE_FAILED", details: response.status };

	let tokens = safe_json_parse(response.body);
	if (!tokens) return { ok: false, error: "INVALID_JSON" };

	return { ok: true, data: tokens };
};

/**
 * Verifies ID Token and matches nonce.
 */
export function verify_id_token(io, tokens, keys, config, handshake, discovery) {
	if (!tokens.id_token) return { ok: false, error: "MISSING_ID_TOKEN" };

	let parts = split(tokens.id_token, ".");
	let header = safe_json_parse(crypto.b64url_decode(parts[0]));
	if (!header) return { ok: false, error: "INVALID_JWT_HEADER" };

	let jwk_res = find_jwk(keys, header.kid);
	if (!jwk_res.ok) return jwk_res;

	let pem_res = crypto.jwk_to_pem(jwk_res.data);
	if (!pem_res.ok) return pem_res;

	// MANDATORY Claims Check: 
	// The issuer in the token MUST match the discovery document, 
	// AND the discovery document MUST match our configured expectation.
	if (discovery.issuer != config.issuer_url) {
		return { ok: false, error: "DISCOVERY_ISSUER_MISMATCH", details: `Expected ${config.issuer_url}, IdP claimed ${discovery.issuer}` };
	}

	let validation_opts = { 
		alg: header.alg,
		now: io.time(),
		iss: config.issuer_url,
		aud: config.client_id
	};

	let result = crypto.verify_jwt(tokens.id_token, pem_res.data, validation_opts);
	if (!result.ok) return result;

	let payload = result.data;

	// OIDC Mandatory Claims Check
	if (!payload.sub) {
		return { ok: false, error: "MISSING_SUB_CLAIM" };
	}

	// Nonce Check
	if (handshake.nonce && payload.nonce != handshake.nonce) {
		return { ok: false, error: "NONCE_MISMATCH" };
	}

	let user_data = {
		sub: payload.sub,
		email: payload.email || payload.sub,
		name: payload.name
	};

	return { ok: true, data: user_data };
};
