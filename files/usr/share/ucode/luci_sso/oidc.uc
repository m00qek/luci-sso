import * as fs from 'fs';
import * as uclient from 'uclient';
import * as crypto from 'luci_sso.crypto';

// --- Internal Helpers ---

function load_cache(path, ttl) {
	try {
		let content = fs.readfile(path);
		if (!content) return null;
		
		let cached = json(content);
		if (!cached || !cached.cached_at) return null;
		
		let now = time();
		if ((now - cached.cached_at) > ttl) return null;
		
		return cached;
	} catch (e) {
		return null;
	}
}

function save_cache(path, config) {
	config.cached_at = time();
	try {
		fs.writefile(path, sprintf("%J", config));
	} catch (e) {
		// Ignore cache write failures
	}
}

function http_get(url) {
	let conn = uclient.connect(url);
	if (!conn) return { error: `Could not connect to ${url}` };

	let res = conn.request("GET");
	if (!res) return { error: `Request to ${url} failed` };
	
	return res;
}

function safe_json_parse(data) {
	if (type(data) == "object" && type(data.read) == "function") {
		data = data.read();
	}
	
	if (type(data) != "string") {
		return { error: "INVALID_INPUT_TYPE", details: type(data) };
	}

	try {
		return json(data);
	} catch (e) {
		return { error: "INVALID_JSON", details: e };
	}
}

// --- Public API ---

/**
 * Fetches and caches OIDC discovery document.
 */
export function discover(io, issuer, options) {
	options = options || {};
	let cache_path = options.cache_path || "/tmp/oidc-discovery.json";
	let ttl = options.ttl || 3600;
	
	// 1. Check cache
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
	
	// 2. Fetch discovery document
	let discovery_url = issuer;
	if (substr(discovery_url, -1) != '/') discovery_url += '/';
	discovery_url += ".well-known/openid-configuration";
	
	let response = io.http_get(discovery_url);
	if (!response) return { error: "NETWORK_ERROR" };
	if (response.error) return response;
	
	if (response.status != 200) {
		return { error: "DISCOVERY_FAILED", details: response.status };
	}
	
	let config = safe_json_parse(response.body);
	if (config.error) return config;

	if (!config.authorization_endpoint) {
		return { error: "INVALID_DISCOVERY_DOCUMENT" };
	}
	
	// 3. Validate required fields
	let required = ["authorization_endpoint", "token_endpoint", "jwks_uri"];
	for (let i, field in required) {
		if (!config[field]) {
			return { error: "MISSING_REQUIRED_FIELD", details: field };
		}
	}
	
	// 4. Cache result
	config.cached_at = io.time();
	io.write_file(cache_path, sprintf("%J", config));
	
	return { config: config };
};

/**
 * Fetches JWK Set from IdP.
 */
export function fetch_jwks(io, jwks_uri) {
	let response = io.http_get(jwks_uri);
	if (!response) return { error: "NETWORK_ERROR" };
	if (response.error) return response;
	
	if (response.status != 200) {
		return { error: "JWKS_FETCH_FAILED", details: response.status };
	}
	
	let jwks = safe_json_parse(response.body);
	if (jwks.error) return jwks;

	if (!jwks.keys || type(jwks.keys) != "array") {
		return { error: "INVALID_JWKS_FORMAT" };
	}
	
	return { keys: jwks.keys };
};

/**
 * Finds the correct JWK by key ID (kid).
 */
export function find_jwk(keys, kid) {
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
export function get_auth_url(io, config, discovery) {
	let pkce = crypto.pkce_pair();
	let state = crypto.b64url_encode(crypto.random(16));

	let params = {
		response_type: "code",
		client_id: config.client_id,
		redirect_uri: config.redirect_uri,
		scope: config.scope,
		state: state,
		code_challenge: pkce.challenge,
		code_challenge_method: "S256"
	};

	let url = discovery.authorization_endpoint;
	let sep = (index(url, '?') == -1) ? '?' : '&';

	for (let k, v in params) {
		url += `${sep}${k}=${io.urlencode(v)}`;
		sep = '&';
	}

	return {
		url: url,
		state: state,
		code_verifier: pkce.verifier
	};
};
