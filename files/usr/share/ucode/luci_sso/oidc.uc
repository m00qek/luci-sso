import * as fs from 'fs';
import * as uclient from 'uclient';
import * as crypto from 'luci_sso.crypto';

// --- Internal Helpers ---

function safe_json_parse(data) {
	let raw = data;
	if (type(data) == "object" && type(data.read) == "function") {
		raw = data.read();
	}
	
	if (type(raw) != "string") {
		return { error: "INVALID_INPUT_TYPE" };
	}

	try {
		return json(raw);
	} catch (e) {
		return { error: "INVALID_JSON" };
	}
}

// --- Public API ---

/**
 * Fetches and caches OIDC discovery document.
 */
export function discover(io, issuer, options) {
	if (type(issuer) != "string") return { error: "INVALID_ISSUER" };

	options = options || {};
	let cache_path = options.cache_path || "/tmp/oidc-discovery.json";
	let ttl = options.ttl || 3600;
	
	// 1. Check cache
	try {
		let content = io.read_file(cache_path);
		if (content) {
			let cached = safe_json_parse(content);
			if (!cached.error && cached.issuer == issuer) {
				let now = io.time();
				if (cached.cached_at && (now - cached.cached_at) <= ttl) {
					return { config: cached };
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
	if (!response || response.error) return { error: "NETWORK_ERROR" };
	
	if (response.status != 200) {
		return { error: "DISCOVERY_FAILED", details: response.status };
	}
	
	let config = safe_json_parse(response.body);
	if (config.error) return config;

	// 3. Strict validation of required fields
	let required = ["authorization_endpoint", "token_endpoint", "jwks_uri"];
	for (let i, field in required) {
		if (type(config[field]) != "string" || length(config[field]) == 0) {
			return { error: "MISSING_REQUIRED_FIELD", details: field };
		}
	}
	
	// 4. Cache result
	config.cached_at = io.time();
	try {
		io.write_file(cache_path, sprintf("%J", config));
	} catch (e) {
		// Ignore cache write failures
	}
	
	return { config: config };
};

/**
 * Fetches JWK Set from IdP.
 */
export function fetch_jwks(io, jwks_uri) {
	let response = io.http_get(jwks_uri);
	if (!response || response.error) return { error: "NETWORK_ERROR" };
	
	if (response.status != 200) {
		return { error: "JWKS_FETCH_FAILED", details: response.status };
	}
	
	let jwks = safe_json_parse(response.body);
	if (jwks.error) return jwks;

	if (type(jwks.keys) != "array") {
		return { error: "INVALID_JWKS_FORMAT" };
	}
	
	return { keys: jwks.keys };
};

/**
 * Finds the correct JWK by key ID (kid).
 */
export function find_jwk(keys, kid) {
	if (type(keys) != "array") return { error: "INVALID_KEYS_INPUT" };

	if (!kid) {
		if (length(keys) > 0) return { jwk: keys[0] };
		return { error: "NO_KEYS_AVAILABLE" };
	}
	
	for (let i, key in keys) {
		if (key.kid == kid) return { jwk: key };
	}
	
	return { error: "KEY_NOT_FOUND", details: kid };
};

/**
 * Generates the authorization URL.
 */
export function get_auth_url(io, config, discovery, params) {
	let query = {
		response_type: "code",
		client_id: config.client_id,
		redirect_uri: config.redirect_uri,
		scope: config.scope,
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
