'use strict';

import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';

/**
 * Implementation of OIDC Discovery and JWKS management.
 * Handles network interaction and caching for IdP metadata.
 */

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
function _read_cache(io, path, ttl, ignore_ttl) {
	try {
		let content = io.read_file(path);
		if (!content) return null;

		let res = encoding.safe_json(content);
		if (!res.ok) return null;

		let data = res.data;
		if (!data || !data.cached_at) return null;

		if (!ignore_ttl && (io.time() - data.cached_at) > ttl) return null;

		return data;
	} catch (e) {
		return null;
	}
}

/**
 * Writes data to cache with a timestamp (Atomic).
 * @private
 */
function _write_cache(io, path, data) {
	try {
		let cache_data = { ...data, cached_at: io.time() };
		
		let res = crypto.random(8);
		if (!res.ok) {
			io.log("error", "Cache write aborted: CSPRNG failure");
			return;
		}
		let tmp_path = `${path}.${crypto.b64url_encode(res.data)}.tmp`;
		
		if (io.write_file(tmp_path, sprintf("%J", cache_data))) {
			if (!io.rename(tmp_path, path)) {
				io.remove(tmp_path);
			}
		}
	} catch (e) {
		io.log("error", `Cache write failure: ${e}`);
	}
}

/**
 * Checks if a URL uses HTTPS.
 * @private
 */
function _is_https(url) {
	return (type(url) == "string" && substr(url, 0, 8) == "https://");
}

/**
 * Fetches and caches OIDC discovery document.
 */
export function discover(io, issuer, options) {
	if (type(issuer) != "string") die("CONTRACT_VIOLATION: issuer must be a string");

	if (!_is_https(issuer)) return { ok: false, error: "INSECURE_ISSUER_URL" };

	options = options || {};
	let cache_path = options.cache_path || get_cache_path(issuer, "discovery");
	let ttl = options.ttl || 86400; // 24 hours default (production standard)

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

	if (!response || response.error || response.status != 200) {
		// RESILIENCE FALLBACK: Try to use stale cache if network failed (W1)
		let stale = _read_cache(io, cache_path, ttl, true);
		if (stale && stale.issuer == issuer) {
			io.log("warn", `Using stale discovery cache due to network failure [id: ${issuer_id}]`);
			return { ok: true, data: stale };
		}

		if (!response || response.error) {
			io.log("warn", `Discovery fetch failed for [id: ${issuer_id}]: ${response?.error || "no response"}`);
			return { ok: false, error: "NETWORK_ERROR" };
		}
		
		io.log("warn", `Discovery fetch HTTP ${response.status} from [id: ${issuer_id}]`);
		return { ok: false, error: "DISCOVERY_FAILED", details: response.status };
	}

	let res = encoding.safe_json(response.body);
	if (!res.ok) {
		io.log("error", `Discovery JSON parse error: ${res.details}`);
		return { ok: false, error: "INVALID_DISCOVERY_DOC" };
	}
	let config = res.data;

	// 2.1 Issuer Validation: The document MUST claim to be the issuer we requested
	if (!config.issuer) {
		io.log("error", `Discovery document missing issuer field from [id: ${issuer_id}]`);
		return { ok: false, error: "DISCOVERY_MISSING_ISSUER" };
	}
	if (config.issuer && config.issuer != issuer) {
		io.log("error", `Discovery issuer mismatch: Requested [id: ${issuer_id}], got [id: ${crypto.safe_id(config.issuer)}]`);
		return { ok: false, error: "DISCOVERY_ISSUER_MISMATCH", 
			 details: `Expected issuer_id ${issuer_id}` };
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

	// OPTIONAL: UserInfo endpoint (RFC 6749 / OIDC)
	if (config.userinfo_endpoint && !_is_https(config.userinfo_endpoint)) {
		io.log("warn", `Insecure userinfo_endpoint ignored from [id: ${issuer_id}]`);
		delete config.userinfo_endpoint;
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
	if (!response || response.error || response.status != 200) {
		// RESILIENCE FALLBACK: Try stale cache
		let stale = _read_cache(io, cache_path, ttl, true);
		if (stale && type(stale.keys) == "array") {
			io.log("warn", `Using stale JWKS cache due to network failure [id: ${uri_id}]`);
			return { ok: true, data: stale.keys };
		}

		if (!response || response.error) {
			io.log("warn", `JWKS fetch failed for [id: ${uri_id}]: ${response?.error || "no response"}`);
			return { ok: false, error: "NETWORK_ERROR" };
		}
		
		io.log("warn", `JWKS fetch HTTP ${response.status} from [id: ${uri_id}]`);
		return { ok: false, error: "JWKS_FETCH_FAILED", details: response.status };
	}

	let res = encoding.safe_json(response.body);
	if (!res.ok || type(res.data.keys) != "array") {
		io.log("error", `JWKS JSON parse error: ${res.details || "Invalid structure"}`);
		return { ok: false, error: "INVALID_JWKS_FORMAT" };
	}
	let jwks = res.data;

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
