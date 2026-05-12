import * as Result from 'luci_sso.result';

/**
 * Implementation of RFC 7515 Base64URL encoding and decoding.
 */

const MAX_UTILS_SIZE = 32768; // 32 KB

/**
 * Maps standard Base64 characters to URL-safe ones.
 * @private
 */
function _map_to_url_safe(str) {
	let res = replace(str, /\+/g, '-');
	return replace(res, /\//g, '_');
};

/**
 * Maps URL-safe characters back to standard Base64.
 * @private
 */
function _map_from_url_safe(str) {
	let res = replace(str, /-/g, '+');
	return replace(res, /_/g, '/');
};

/**
 * Adds padding characters to a Base64 string if needed.
 * @private
 */
function _add_padding(str) {
	let pad = (4 - (length(str) % 4)) % 4;
	for (let i = 0; i < pad; i++) {
		str += '=';
	}
	return str;
};

/**
 * Removes all padding characters from a Base64 string.
 * @private
 */
function _strip_padding(str) {
	return replace(str, /=/g, '');
};

/**
 * Converts Base64URL to Standard Base64 with padding.
 * Internal helper for decoding operations.
 * @private
 */
function b64url_to_b64(str) {
	if (length(str) == 0)
    return "";
	
	// Validate Base64URL charset: [A-Za-z0-9_-]
	if (!match(str, /^[A-Za-z0-9_-]+$/))
    return null;
	
	return _add_padding(_map_from_url_safe(str));
};

/**
 * Decodes a Base64URL string to a raw string.
 * Enforces a strict size limit to prevent OOM.
 * 
 * @param {string} str - Base64URL string
 * @returns {object} - Result Object {ok, data/error}
 */
export function b64url_decode(str) {
	if (type(str) != "string")
    die("CONTRACT_VIOLATION: b64url_decode expects string");
	
	if (length(str) > MAX_UTILS_SIZE)
    return Result.err("TOKEN_TOO_LARGE");

	let b64 = b64url_to_b64(str);
	if (b64 == null)
    return Result.err("INVALID_ENCODING");

	let decoded = b64dec(b64);
	if (decoded == null)
    return Result.err("INVALID_ENCODING");

	return Result.ok(decoded);
};

/**
 * Encodes a raw string to Base64URL.
 * 
 * @param {string} str - Raw binary string
 * @returns {object} - Result Object {ok, data/error}
 */
export function b64url_encode(str) {
	if (type(str) != "string")
    die("CONTRACT_VIOLATION: b64url_encode expects string");
	
	let b64 = b64enc(str);
	if (b64 == null)
    return Result.err("ENCODE_ERROR");

	return Result.ok(_strip_padding(_map_to_url_safe(b64)));
};

/**
 * Extracts exactly N bytes from a string.
 * This is byte-safe and avoids UTF-8 character boundary issues.
 * 
 * @param {string} data - Raw binary data string
 * @param {number} len - Number of bytes to extract
 * @returns {object} - Result Object {ok, data/error}
 */
export function binary_truncate(data, len) {
	if (type(data) != "string")
    die("CONTRACT_VIOLATION: binary_truncate expects string data");

	if (type(len) != "int")
    die("CONTRACT_VIOLATION: binary_truncate expects integer length");

	if (len > length(data))
    die("CONTRACT_VIOLATION: truncation length exceeds data length");

	// substr() in ucode is byte-safe for binary strings
	return Result.ok(substr(data, 0, len));
};

/**
 * Pure JSON decoder that returns a Result Object.
 * Handles both strings and stream-like objects with a .read() method.
 * 
 * @param {string|object} data - Input to decode.
 * @returns {object} - Result Object {ok, data/error}
 */
export function safe_json(data) {
	let raw = (type(data) == "object" && type(data.read) == "function") ? data.read() : data;
	
	// If it's a Result object (e.g. from b64url_decode), extract data
	if (type(raw) == "object" && raw.ok != null) {
		if (!raw.ok)
      return raw;

		raw = raw.data;
	}

	if (type(raw) != "string") return Result.err("INVALID_TYPE");

	try {
		let parsed = json(raw);
		if (parsed == null)
      return Result.err("PARSE_ERROR", "JSON decoded to null");

		return Result.ok(parsed);
	} catch (e) {
		return Result.err("PARSE_ERROR", e);
	}
};

/**
 * Normalizes a URL for comparison.
 * Lowercases the scheme/host and removes trailing slashes.
 * Per RFC 3986, the path component is case-sensitive.
 * 
 * @param {string} url - The URL to normalize
 * @returns {object} - Result Object {ok, data/error}
 */
export function normalize_url(url) {
	if (type(url) != "string")
    return Result.err("INVALID_ARGUMENT", "normalize_url expects string");
	
	let res = url;
	let m = match(url, /^([A-Za-z]+:\/\/)([^/]+)(.*)$/);
	if (!m)
    return Result.err("MALFORMED_URL", url);

	let scheme = lc(m[1]);
	let host = lc(m[2]);
	let path = m[3];

	// Strip default ports per RFC 3986 §6.2.3
	if (scheme == "https://") {
		host = replace(host, /:443$/, "");
	} else if (scheme == "http://") {
		host = replace(host, /:80$/, "");
	}

	res = scheme + host + path;

	// Remove trailing slashes
	res = replace(res, /\/+$/, "");
	return Result.ok(res);
};

/**
 * Normalizes a 'sub' claim for comparison.
 * Normalizing to lowercase ensures interoperability.
 * 
 * @param {string} sub - The sub claim to normalize
 * @returns {object} - Result Object {ok, data/error}
 */
export function normalize_sub(sub) {
	if (type(sub) != "string")
    return Result.err("INVALID_ARGUMENT", "normalize_sub expects string");

	return Result.ok(lc(sub));
};

/**
 * Checks if a URL uses the HTTPS scheme (case-insensitive).
 * Per RFC 3986 §3.1, schemes are case-insensitive.
 * 
 * @param {string} url - The URL to check
 * @returns {boolean} - True if HTTPS
 */
export function is_https(url) {
	return (type(url) == "string" && lc(substr(url, 0, 8)) == "https://");
};
