import * as fs from 'fs';
import * as uclient from 'uclient';
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
 * Generates a unique cache path for an issuer to avoid collisions.
 * @private
 */
function get_cache_path(issuer) {
	// Simple hash-like string from issuer
	let h = crypto.b64url_encode(crypto.sha256(issuer));
	return `/tmp/oidc-discovery-${substr(h, 0, 8)}.json`;
}

// --- Public API ---

/**
 * Fetches and caches OIDC discovery document.
 * 
 * @param {object} io - I/O provider
 * @param {string} issuer - IdP issuer URL
 * @param {object} [options] - Cache and TTL options
 * @returns {object} - Result Object {ok, data/error}
 */
export function discover(io, issuer, options) {
	validate_io(io);
	if (type(issuer) != "string") die("CONTRACT_VIOLATION: issuer must be a string");

	options = options || {};
	let cache_path = options.cache_path || get_cache_path(issuer);
	let ttl = options.ttl || 3600;
	
	// 1. Check cache
	try {
		let content = io.read_file(cache_path);
		if (content) {
			let cached = safe_json_parse(content);
			if (cached && cached.issuer == issuer) {
				let now = io.time();
				if (cached.cached_at && (now - cached.cached_at) <= ttl) {
					return { ok: true, data: cached };
				}
			}
		}
	} catch (e) {
		// Ignore cache read errors
	}
	
	// 2. Fetch discovery document
	let discovery_url = issuer;
	if (substr(discovery_url, -1) != '/') discovery_url += '/';
	discovery_url += ".well-known/openid-configuration";
	
	let response = io.http_get(discovery_url);
	if (!response || response.error) return { ok: false, error: "NETWORK_ERROR" };
	
	if (response.status != 200) {
		return { ok: false, error: "DISCOVERY_FAILED", details: response.status };
	}
	
	let config = safe_json_parse(response.body);
	if (!config) return { ok: false, error: "INVALID_JSON" };

	// 3. Strict validation of required fields
	let required = ["authorization_endpoint", "token_endpoint", "jwks_uri"];
	for (let i, field in required) {
		if (type(config[field]) != "string" || length(config[field]) == 0) {
			return { ok: false, error: "MISSING_REQUIRED_FIELD", details: field };
		}
	}
	
	// 4. Cache result
	config.cached_at = io.time();
	try {
		io.write_file(cache_path, sprintf("%J", config));
	} catch (e) {
		// Ignore cache write failures
	}
	
	return { ok: true, data: config };
};

/**
 * Fetches JWK Set from IdP.
 * 
 * @param {object} io - I/O provider
 * @param {string} jwks_uri - URI to JWKS endpoint
 * @returns {object} - Result Object {ok, data/error}
 */
export function fetch_jwks(io, jwks_uri) {
	validate_io(io);
	if (type(jwks_uri) != "string") die("CONTRACT_VIOLATION: jwks_uri must be a string");

	let response = io.http_get(jwks_uri);
	if (!response || response.error) return { ok: false, error: "NETWORK_ERROR" };
	
	if (response.status != 200) {
		return { ok: false, error: "JWKS_FETCH_FAILED", details: response.status };
	}
	
	let jwks = safe_json_parse(response.body);
	if (!jwks) return { ok: false, error: "INVALID_JSON" };

	if (type(jwks.keys) != "array") {
		return { ok: false, error: "INVALID_JWKS_FORMAT" };
	}
	
	return { ok: true, data: jwks.keys };
};

/**
 * Finds the correct JWK by key ID (kid).
 * 
 * @param {array} keys - Array of JWK objects
 * @param {string} [kid] - Key ID to look for
 * @returns {object} - Result Object {ok, data/error}
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
 * 
 * @param {object} io - I/O provider
 * @param {object} config - UCI configuration
 * @param {object} discovery - OIDC discovery document
 * @param {object} params - Handshake parameters {state, nonce, challenge}
 * @returns {string} - Full authorization URL
 */
export function get_auth_url(io, config, discovery, params) {
	if (type(config) != "object" || type(discovery) != "object" || type(params) != "object") {
		die("CONTRACT_VIOLATION: get_auth_url expects objects");
	}

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
		url += `${sep}${k}=${uclient.urlencode(v)}`;
		sep = '&';
	}

	return url;
};

/**
 * Exchanges authorization code for tokens.
 * 
 * @param {object} io - I/O provider
 * @param {object} config - UCI configuration
 * @param {object} discovery - OIDC discovery document
 * @param {string} code - Authorization code from IdP
 * @param {string} verifier - PKCE code verifier
 * @returns {object} - Result Object {ok, data/error}
 */
export function exchange_code(io, config, discovery, code, verifier) {
	validate_io(io);
	if (type(io.http_post) != "function") die("CONTRACT_VIOLATION: IO must support http_post");
	
	let body = {
		grant_type: "authorization_code",
		client_id: config.client_id,
		client_secret: config.client_secret,
		redirect_uri: config.redirect_uri,
		code: code,
		code_verifier: verifier
	};

	// Form-encode body
	let encoded_body = "";
	let sep = "";
	for (let k, v in body) {
		if (v == null) continue;
		encoded_body += `${sep}${k}=${uclient.urlencode(v)}`;
		sep = "&";
	}

	let response = io.http_post(discovery.token_endpoint, {
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: encoded_body
	});

	if (!response || response.error) return { ok: false, error: "NETWORK_ERROR" };
	if (response.status != 200) {
		return { ok: false, error: "TOKEN_EXCHANGE_FAILED", details: response.status, body: response.body };
	}

	let tokens = safe_json_parse(response.body);
	if (!tokens) return { ok: false, error: "INVALID_JSON" };

	return { ok: true, data: tokens };
};

/**
 * Verifies ID Token and matches nonce.
 * 
 * @param {object} io - I/O provider
 * @param {object} tokens - Token response from exchange_code
 * @param {array} keys - JWK Set
 * @param {object} config - UCI configuration
 * @param {object} handshake - Original handshake data
 * @returns {object} - Result Object {ok, data/error}
 */
export function verify_id_token(io, tokens, keys, config, handshake) {
	if (!tokens.id_token) return { ok: false, error: "MISSING_ID_TOKEN" };

	// 1. Get Key
	let parts = split(tokens.id_token, ".");
	let header = safe_json_parse(crypto.b64url_decode(parts[0]));
	if (!header) return { ok: false, error: "INVALID_JWT_HEADER" };

	let jwk_res = find_jwk(keys, header.kid);
	if (!jwk_res.ok) return jwk_res;

	let pem_res = crypto.jwk_to_pem(jwk_res.data);
	if (!pem_res.ok) return pem_res;

	// 2. Verify Sig and Claims
	let result = crypto.verify_jwt(tokens.id_token, pem_res.data, {
		alg: header.alg,
		iss: config.issuer_url,
		aud: config.client_id
	});

	if (!result.ok) return result;

	// 3. Nonce Check
	if (handshake.nonce && result.data.nonce != handshake.nonce) {
		return { ok: false, error: "NONCE_MISMATCH" };
	}

	return result;
};