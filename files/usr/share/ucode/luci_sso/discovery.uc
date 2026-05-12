'use strict';

import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';

/**
 * Implementation of OIDC Discovery and JWKS management.
 * Handles network interaction and caching for IdP metadata.
 */

/**
 * Generates a unique cache path for an identifier (issuer or JWKS URI).
 * @private
 */
function get_cache_path(id_res, prefix) {
	if (!id_res.ok) return null;
	let h_res = encoding.b64url_encode(crypto.hash_sha256(id_res.data));
	if (!h_res.ok) return null;
	return `/var/run/luci-sso/oidc-${prefix}-${substr(h_res.data, 0, 32)}.json`;
};

/**
 * Reads and validates a cached object.
 * @private
 */
function _read_cache(io, path, ttl, ignore_ttl) {
	if (!path) return null;
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
};

/**
 * Writes data to cache with a timestamp (Atomic).
 * @private
 */
function _write_cache(io, path, data) {
	if (!path) return;
	try {
		let cache_data = { ...data, cached_at: io.time() };

		let res = crypto.random(8);
		if (!res.ok) {
			io.log("error", "Cache write aborted: CSPRNG failure");
			return;
		}
		let b64_res = encoding.b64url_encode(res.data);
		if (!b64_res.ok) return;

		let tmp_path = `${path}.${b64_res.data}.tmp`;

		if (io.write_file(tmp_path, sprintf("%J", cache_data))) {
			if (!io.rename(tmp_path, path)) {
				io.remove(tmp_path);
			}
		}
	} catch (e) {
		io.log("error", `Cache write failure: ${e}`);
	}
};

/**
 * Fetches and caches OIDC discovery document.
 */
export function discover(io, issuer, options) {
	if (!encoding.is_https(issuer)) return Result.err("INSECURE_ISSUER_URL");

	options = options || {};
	let normalized_issuer_res = encoding.normalize_url(issuer);
	if (!normalized_issuer_res.ok) return normalized_issuer_res;
	let normalized_issuer = normalized_issuer_res.data;

	let cache_path = options.cache_path || get_cache_path(normalized_issuer_res, "discovery");
	let ttl = options.ttl || 86400; // 24 hours default (production standard)

	let cached = _read_cache(io, cache_path, ttl);
	if (cached && cached.issuer) {
		let cached_issuer_res = encoding.normalize_url(cached.issuer);
		if (cached_issuer_res.ok && crypto.constant_time_eq(cached_issuer_res.data, normalized_issuer)) {
			return Result.ok(cached);
		}
	}

	// The fetch URL might be different from the logical issuer URL (Split-Horizon)
	let fetch_url = options.internal_issuer_url || issuer;
	if (!encoding.is_https(fetch_url)) return Result.err("INSECURE_FETCH_URL");

	if (substr(fetch_url, -1) != '/') fetch_url += '/';
	fetch_url += ".well-known/openid-configuration";

	let res_http = io.http_get(fetch_url, { verify: true });
	let issuer_id = crypto.safe_id(normalized_issuer);

	if (!res_http.ok || res_http.data.status != 200) {
		// RESILIENCE FALLBACK: Try to use stale cache if network failed (W1)
		let stale = _read_cache(io, cache_path, ttl, true);
		if (stale && stale.issuer) {
			let stale_issuer_res = encoding.normalize_url(stale.issuer);
			if (stale_issuer_res.ok && crypto.constant_time_eq(stale_issuer_res.data, normalized_issuer)) {
				io.log("warn", `Using stale discovery cache due to network failure [id: ${issuer_id}]`);
				return Result.ok(stale);
			}
		}

		if (!res_http.ok) {
			io.log("warn", `Discovery fetch failed for [id: ${issuer_id}]: ${res_http.error}`);
			return Result.err("NETWORK_ERROR");
		}

		io.log("warn", `Discovery fetch HTTP ${res_http.data.status} from [id: ${issuer_id}]`);
		return Result.err("DISCOVERY_FAILED", { http_status: res_http.data.status });
	}

	let response = res_http.data;

	let res = encoding.safe_json(response.body);
	if (!res.ok) {
		io.log("error", `Discovery JSON parse error: ${res.details}`);
		return Result.err("INVALID_DISCOVERY_DOC");
	}
	let config = res.data;

	// 2.1 Issuer Validation: The document MUST claim to be the issuer we requested
	if (!config.issuer) {
		io.log("error", `Discovery document missing issuer field from [id: ${issuer_id}]`);
		return Result.err("DISCOVERY_MISSING_ISSUER");
	}
	
	let config_issuer_res = encoding.normalize_url(config.issuer);
	if (!config_issuer_res.ok || !crypto.constant_time_eq(config_issuer_res.data, normalized_issuer)) {
		io.log("error", `Discovery issuer mismatch: Requested [id: ${issuer_id}], got [id: ${config_issuer_res.ok ? crypto.safe_id(config_issuer_res.data) : "INVALID"}]`);
		return Result.err("DISCOVERY_ISSUER_MISMATCH", 
			 `Expected issuer_id ${issuer_id}` );
	}

	io.log("info", `Discovery successful for [id: ${issuer_id}]`);

	let required = ["authorization_endpoint", "token_endpoint", "jwks_uri"];
	for (let i, field in required) {
		if (type(config[field]) != "string" || length(config[field]) == 0) {
			return Result.err("MISSING_REQUIRED_FIELD", field);
		}
		if (!encoding.is_https(config[field])) {
			return Result.err("INSECURE_ENDPOINT", field);
		}
	}

	// OPTIONAL: UserInfo endpoint (RFC 6749 / OIDC)
	if (config.userinfo_endpoint && !encoding.is_https(config.userinfo_endpoint)) {
		io.log("warn", `Insecure userinfo_endpoint ignored from [id: ${issuer_id}]`);
		delete config.userinfo_endpoint;
	}

	// OPTIONAL: RP-Initiated Logout support (RFC 7522 / OIDC)
	if (config.end_session_endpoint && !encoding.is_https(config.end_session_endpoint)) {
		io.log("warn", `Insecure end_session_endpoint ignored from [id: ${issuer_id}]`);
		delete config.end_session_endpoint;
	}

	_write_cache(io, cache_path, config);

	return Result.ok(config);
};

/**
 * Fetches JWK Set from IdP with caching.
 */
export function fetch_jwks(io, jwks_uri, options) {
	if (type(jwks_uri) != "string") die("CONTRACT_VIOLATION: jwks_uri must be a string");

	let normalized_uri_res = encoding.normalize_url(jwks_uri);
	if (!normalized_uri_res.ok) return normalized_uri_res;
	let normalized_uri = normalized_uri_res.data;

	if (!encoding.is_https(normalized_uri)) return Result.err("INSECURE_JWKS_URI");

	options = options || {};
	let cache_path = options.cache_path || get_cache_path(normalized_uri_res, "jwks");
	let ttl = options.ttl || 86400; // 24 hours default
	let uri_id = crypto.safe_id(normalized_uri);

	if (!options.force) {
		let cached = _read_cache(io, cache_path, ttl);
		if (cached && type(cached.keys) == "array") {
			io.log("info", `JWKS loaded from cache for [id: ${uri_id}]`);
			return Result.ok(cached.keys);
		}
	}

	let res_http = io.http_get(jwks_uri, { verify: true });
	if (!res_http.ok || res_http.data.status != 200) {
		// RESILIENCE FALLBACK: Try stale cache
		let stale = _read_cache(io, cache_path, ttl, true);
		if (stale && type(stale.keys) == "array") {
			io.log("warn", `Using stale JWKS cache due to network failure [id: ${uri_id}]`);
			return Result.ok(stale.keys);
		}

		if (!res_http.ok) {
			io.log("warn", `JWKS fetch failed for [id: ${uri_id}]: ${res_http.error}`);
			return Result.err("NETWORK_ERROR");
		}

		io.log("warn", `JWKS fetch HTTP ${res_http.data.status} from [id: ${uri_id}]`);
		return Result.err("JWKS_FETCH_FAILED", { http_status: res_http.data.status });
	}

	let response = res_http.data;

	let res = encoding.safe_json(response.body);
	if (!res.ok || type(res.data.keys) != "array") {
		io.log("error", `JWKS JSON parse error: ${res.details || "Invalid structure"}`);
		return Result.err("INVALID_JWKS_FORMAT");
	}
	let jwks = res.data;

	io.log("info", `JWKS successfully fetched: ${length(jwks.keys)} keys from [id: ${uri_id}]`);

	_write_cache(io, cache_path, jwks);

	return Result.ok(jwks.keys);
};

/**
 * Finds the correct JWK by key ID (kid).
 */
export function find_jwk(keys, kid) {
	if (type(keys) != "array") die("CONTRACT_VIOLATION: keys must be an array");
		if (!kid) {
			if (length(keys) > 0) return Result.ok(keys[0]);
			return Result.err("NO_KEYS_AVAILABLE");
		}
		for (let i, key in keys) {
			if (crypto.constant_time_eq(key.kid, kid)) return Result.ok(key);
		}
		return Result.err("KEY_NOT_FOUND", kid);
	};
