"use strict";

import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import { INSECURE_ISSUER_URL, INSECURE_FETCH_URL, DISCOVERY_NETWORK_ERROR, DISCOVERY_FAILED, INVALID_DISCOVERY_DOC, DISCOVERY_MISSING_ISSUER, DISCOVERY_ISSUER_MISMATCH, DISCOVERY_MISSING_ENDPOINT, INSECURE_ENDPOINT, INSECURE_JWKS_URI, JWKS_FETCH_FAILED, JWKS_NETWORK_ERROR, INVALID_JWKS_FORMAT, KEY_NOT_FOUND, NO_KEYS_AVAILABLE } from 'luci_sso.errors';

/**
 * Implementation of OIDC Discovery and JWKS management.
 * Handles network interaction and caching for IdP metadata.
 */

/**
 * Generates a unique cache path for an identifier (issuer or JWKS URI).
 * @private
 */
function get_cache_path(native, id_res, prefix) {
	if (!id_res.ok) return null;
	let hash_res = crypto.hash_sha256(native, id_res.data);
	if (!hash_res.ok) return hash_res;
	let h_res = encoding.b64url_encode(hash_res.data);
	if (!h_res.ok) return null;
	return `/var/run/luci-sso/oidc-${prefix}-${substr(h_res.data, 0, 32)}.json`;
}

/**
 * Reads and validates a cached object.
 * @private
 */
function _read_cache(deps, path, ttl, ignore_ttl) {
	if (!path) return null;
	try {
		let content = deps.fs.readfile(path);
		if (!content) return null;

		let res = encoding.safe_json(content);
		if (!res.ok) return null;

		let data = res.data;
		if (!data || !data.cached_at) return null;

		if (!ignore_ttl && (deps.clock.time() - data.cached_at) > ttl) return null;

		return data;
	} catch (e) {
		return null;
	}
}

/**
 * Writes data to cache with a timestamp (Atomic).
 * @private
 */
function _write_cache(deps, path, data) {
	if (!path) return;
	try {
		let cache_data = { ...data, cached_at: deps.clock.time() };

		let res = crypto.random(deps.native, 8);
		if (!res.ok) {
			deps.log("error", "Cache write aborted: CSPRNG failure");
			return;
		}
		let b64_res = encoding.b64url_encode(res.data);
		if (!b64_res.ok) return;

		let tmp_path = `${path}.${b64_res.data}.tmp`;

		if (deps.fs.writefile(tmp_path, sprintf("%J", cache_data))) {
			if (!deps.fs.rename(tmp_path, path)) {
				deps.fs.unlink(tmp_path);
			}
		}
	} catch (e) {
		deps.log("error", `Cache write failure: ${e}`);
	}
}

/**
 * The URL the discovery document is fetched from: the issuer's own, or, for
 * split-horizon, the internal origin with the issuer's path kept
 * (https://kc.example.com/realms/home + internal https://10.0.0.5:8443
 * -> https://10.0.0.5:8443/realms/home/.well-known/openid-configuration).
 *
 * @param {string} issuer - The configured issuer_url
 * @param {string} [internal_issuer_url] - The origin to fetch from instead
 * @returns {object} - Result: ok(url), or err(INSECURE_ISSUER_URL or INSECURE_FETCH_URL)
 */
export function discovery_url(issuer, internal_issuer_url) {
	if (!encoding.is_https(issuer)) return Result.err(INSECURE_ISSUER_URL);

	let fetch_url = issuer;
	if (internal_issuer_url) {
		if (!encoding.is_https(internal_issuer_url)) return Result.err(INSECURE_FETCH_URL);
		let int_res = encoding.split_origin(internal_issuer_url);
		let iss_res = encoding.split_origin(issuer);
		if (!int_res.ok || !iss_res.ok) return Result.err(INSECURE_FETCH_URL);
		fetch_url = int_res.data.origin + iss_res.data.rest;
	}
	if (!encoding.is_https(fetch_url)) return Result.err(INSECURE_FETCH_URL);

	if (substr(fetch_url, -1) != "/") fetch_url += "/";
	return Result.ok(fetch_url + ".well-known/openid-configuration");
};

/**
 * A copy of a discovery document for the router's back channel. With
 * split-horizon, the endpoints the router itself calls (token, JWK Set,
 * UserInfo) are moved from the issuer's origin to the internal one, with
 * path and query kept verbatim; endpoints on other hosts (e.g. Google's
 * googleapis.com) are left alone. The authorization and end-session
 * endpoints are browser redirects and are never rewritten.
 *
 * @param {object} doc - A discovery document from discover()
 * @param {string} issuer - The configured issuer_url
 * @param {string} [internal_issuer_url] - The internal origin, or null
 * @returns {object} - The copy; `doc` is not changed
 */
export function backchannel(doc, issuer, internal_issuer_url) {
	let out = { ...doc };
	if (internal_issuer_url) {
		for (let k in [ "token_endpoint", "jwks_uri", "userinfo_endpoint" ]) {
			if (type(out[k]) == "string")
				out[k] = encoding.rebase_origin(out[k], issuer, internal_issuer_url);
		}
	}
	return out;
};

/**
 * Fetches and caches OIDC discovery document.
 *
 * options: { internal_issuer_url, cache_path, ttl, no_cache }. With no_cache,
 * the cache is neither read, nor used as a stale fallback, nor written: the
 * settings page's connection test fetches the document as it is now, and
 * changes nothing on the router.
 *
 * A failure's details say what went wrong, for the connection test (a login
 * only reports OIDC_DISCOVERY_FAILED): DISCOVERY_NETWORK_ERROR carries the
 * transport cause ("HTTP_REQUEST_FAILED (TIMED_OUT)"), DISCOVERY_FAILED
 * { http_status: 502, upstream_status }, DISCOVERY_ISSUER_MISMATCH
 * { issuer_id, declared, near_miss }, where `declared` is the document's
 * issuer (a string, or null) and near_miss says the two differ only in a
 * trailing slash, letter case or default port.
 */
export function discover(deps, issuer, options) {
	options = options || {};

	let url_res = discovery_url(issuer, options.internal_issuer_url);
	if (!url_res.ok) return url_res;
	let fetch_url = url_res.data;

	// OIDC Discovery §4.3: the document's issuer MUST be identical to the
	// issuer URL we are configured with. The cache is keyed on, and every
	// cached document is checked against, that exact string, so a document
	// cached by an earlier version that compared normalized URLs is ignored
	// (and refetched) unless its issuer is identical too.
	let use_cache = !options.no_cache;
	let cache_path = use_cache ? (options.cache_path || get_cache_path(deps.native, Result.ok(issuer), "discovery")) : null;
	let ttl = options.ttl || 86400; // 24 hours default (production standard)

	let cached = _read_cache(deps, cache_path, ttl);
	if (cached && cached.issuer === issuer) {
		return Result.ok(cached);
	}

	// The cache key and the issuer check below use the public issuer, also
	// when the document is fetched from the internal origin.
	let res_http = deps.http.get(fetch_url, { verify: true });
	let issuer_id = crypto.safe_id(deps.native, issuer);

	if (!res_http.ok || res_http.data.status != 200) {
		// If the IdP is unreachable, serve a stale cached document rather than fail the login.
		let stale = _read_cache(deps, cache_path, ttl, true);
		if (stale && stale.issuer === issuer) {
			deps.log("warn", `Using stale discovery cache due to network failure [id: ${issuer_id}]`);
			return Result.ok(stale);
		}

		if (!res_http.ok) {
			deps.log("warn", `Discovery fetch failed for [id: ${issuer_id}]: ${Result.describe(res_http)}`);
			return Result.err(DISCOVERY_NETWORK_ERROR, Result.describe(res_http));
		}

		deps.log("warn", `Discovery fetch HTTP ${res_http.data.status} from [id: ${issuer_id}]`);
		return Result.err(DISCOVERY_FAILED, { http_status: 502, upstream_status: res_http.data.status });
	}

	let response = res_http.data;

	let res = encoding.safe_json(response.body);
	if (!res.ok || type(res.data) != "object") {
		deps.log("error", `Discovery JSON parse error: ${res.details || "not a JSON object"}`);
		return Result.err(INVALID_DISCOVERY_DOC);
	}
	let config = res.data;

	// 2.1 Issuer Validation: The document MUST claim to be the issuer we requested
	if (!config.issuer) {
		deps.log("error", `Discovery document missing issuer field from [id: ${issuer_id}]`);
		return Result.err(DISCOVERY_MISSING_ISSUER);
	}

	if (config.issuer !== issuer) {
		// The issuer is configuration, not a secret: log both values so the
		// admin can see exactly what to copy into issuer_url.
		let doc_issuer = (type(config.issuer) == "string") ? `"${encoding.log_safe(config.issuer)}"` : `(${type(config.issuer)})`;
		// A near miss (trailing slash, letter case, default port) is the
		// usual upgrade trap: say so, since the two can look identical.
		let hint = "";
		let conf_norm = encoding.normalize_url(issuer), doc_norm = encoding.normalize_url(config.issuer);
		let near_miss = (conf_norm.ok && doc_norm.ok && conf_norm.data === doc_norm.data);
		if (near_miss)
			hint = "; they differ only in a trailing slash, letter case or default port: set issuer_url to exactly the declared value";
		deps.log("error", `DISCOVERY_ISSUER_MISMATCH: issuer_url is "${encoding.log_safe(issuer)}" but the discovery document declares ${doc_issuer}${hint} [id: ${issuer_id}]`);
		return Result.err(DISCOVERY_ISSUER_MISMATCH, {
			issuer_id,
			declared: (type(config.issuer) == "string") ? config.issuer : null,
			near_miss
		});
	}

	let required = ["authorization_endpoint", "token_endpoint", "jwks_uri"];
	for (let i, field in required) {
		if (type(config[field]) != "string" || length(config[field]) == 0) {
			deps.log("error", `DISCOVERY_MISSING_ENDPOINT: the discovery document has no ${field} [id: ${issuer_id}]`);
			return Result.err(DISCOVERY_MISSING_ENDPOINT, field);
		}
		if (!encoding.is_https(config[field])) {
			deps.log("error", `INSECURE_ENDPOINT: ${field} in the discovery document is not HTTPS: "${encoding.log_safe(config[field], 100)}" [id: ${issuer_id}]`);
			return Result.err(INSECURE_ENDPOINT, field);
		}
	}

	deps.log("info", `Discovery successful for [id: ${issuer_id}]`);

	// OPTIONAL: UserInfo endpoint (RFC 6749 / OIDC)
	if (config.userinfo_endpoint && !encoding.is_https(config.userinfo_endpoint)) {
		deps.log("warn", `Insecure userinfo_endpoint ignored from [id: ${issuer_id}]`);
		delete config.userinfo_endpoint;
	}

	// OPTIONAL: RP-Initiated Logout support (RFC 7522 / OIDC)
	if (config.end_session_endpoint && !encoding.is_https(config.end_session_endpoint)) {
		deps.log("warn", `Insecure end_session_endpoint ignored from [id: ${issuer_id}]`);
		delete config.end_session_endpoint;
	}

	_write_cache(deps, cache_path, config);

	return Result.ok(config);
};

/**
 * Fetches JWK Set from IdP with caching.
 *
 * options: { cache_path, ttl, force, no_cache }. force skips the fresh cache
 * but keeps the stale fallback and the write; no_cache, for the connection
 * test, neither reads nor writes the cache at all. A failure's details say
 * what went wrong, as for discover(): JWKS_NETWORK_ERROR carries the
 * transport cause, JWKS_FETCH_FAILED { http_status: 502, upstream_status }.
 */
export function fetch_jwks(deps, jwks_uri, options) {
	if (type(jwks_uri) != "string") die("CONTRACT_VIOLATION: jwks_uri must be a string");

	let normalized_uri_res = encoding.normalize_url(jwks_uri);
	if (!normalized_uri_res.ok) return normalized_uri_res;
	let normalized_uri = normalized_uri_res.data;

	if (!encoding.is_https(normalized_uri)) return Result.err(INSECURE_JWKS_URI);

	options = options || {};
	let use_cache = !options.no_cache;
	let cache_path = use_cache ? (options.cache_path || get_cache_path(deps.native, normalized_uri_res, "jwks")) : null;
	let ttl = options.ttl || 86400; // 24 hours default
	let uri_id = crypto.safe_id(deps.native, normalized_uri);

	if (!options.force) {
		let cached = _read_cache(deps, cache_path, ttl);
		if (cached && type(cached.keys) == "array") {
			deps.log("info", `JWKS loaded from cache for [id: ${uri_id}]`);
			return Result.ok(cached.keys);
		}
	}

	let res_http = deps.http.get(jwks_uri, { verify: true });
	if (!res_http.ok || res_http.data.status != 200) {
		// If the IdP is unreachable, serve stale cached keys rather than fail the login.
		let stale = _read_cache(deps, cache_path, ttl, true);
		if (stale && type(stale.keys) == "array") {
			deps.log("warn", `Using stale JWKS cache due to network failure [id: ${uri_id}]`);
			return Result.ok(stale.keys);
		}

		if (!res_http.ok) {
			deps.log("warn", `JWKS fetch failed for [id: ${uri_id}]: ${Result.describe(res_http)}`);
			return Result.err(JWKS_NETWORK_ERROR, Result.describe(res_http));
		}

		deps.log("warn", `JWKS fetch HTTP ${res_http.data.status} from [id: ${uri_id}]`);
		return Result.err(JWKS_FETCH_FAILED, { http_status: 502, upstream_status: res_http.data.status });
	}

	let response = res_http.data;

	let res = encoding.safe_json(response.body);
	if (!res.ok || type(res.data) != "object" || type(res.data.keys) != "array") {
		deps.log("error", `JWKS JSON parse error: ${res.details || "Invalid structure"}`);
		return Result.err(INVALID_JWKS_FORMAT);
	}
	let jwks = res.data;

	deps.log("info", `JWKS successfully fetched: ${length(jwks.keys)} keys from [id: ${uri_id}]`);

	_write_cache(deps, cache_path, jwks);

	return Result.ok(jwks.keys);
};

/**
 * Finds the correct JWK by key ID (kid).
 */
export function find_jwk(keys, kid) {
	if (type(keys) != "array") die("CONTRACT_VIOLATION: keys must be an array");
	if (!kid) {
		if (length(keys) > 0) return Result.ok(keys[0]);
		return Result.err(NO_KEYS_AVAILABLE);
	}
	for (let i, key in keys) {
		if (key.kid === kid) return Result.ok(key);
	}
	return Result.err(KEY_NOT_FOUND, kid);
};
