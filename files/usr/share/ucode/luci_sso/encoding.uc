'use strict';

import * as Result from 'luci_sso.result';

/**
 * Implementation of RFC 7515 Base64URL encoding and decoding.
 * Pure utility module with no external side effects.
 */

const MAX_UTILS_SIZE = 32768; // 32 KB

/**
 * Maps standard Base64 characters to URL-safe ones.
 * @private
 */
function _map_to_url_safe(str) {
	let res = replace(str, /\+/g, '-');
	return replace(res, /\//g, '_');
}

/**
 * Maps URL-safe characters back to standard Base64.
 * @private
 */
function _map_from_url_safe(str) {
	let res = replace(str, /-/g, '+');
	return replace(res, /_/g, '/');
}

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
}

/**
 * Removes all padding characters from a Base64 string.
 * @private
 */
function _strip_padding(str) {
	return replace(str, /=/g, '');
}

/**
 * Converts Base64URL to Standard Base64 with padding.
 * Internal helper for decoding operations.
 * @private
 */
function b64url_to_b64(str) {
	if (type(str) != "string") return null;
	if (length(str) == 0) return "";
	
	// Validate Base64URL charset: [A-Za-z0-9_-]
	if (!match(str, /^[A-Za-z0-9_-]+$/)) return null;
	
	return _add_padding(_map_from_url_safe(str));
}

/**
 * Decodes a Base64URL string to a raw string.
 * Enforces a strict size limit to prevent OOM.
 * 
 * @param {string} str - Base64URL string
 * @returns {string} - Raw binary string or null
 */
export function b64url_decode(str) {
	if (type(str) != "string") die("CONTRACT_VIOLATION: b64url_decode expects string");
	
	if (length(str) > MAX_UTILS_SIZE) return null;

	let b64 = b64url_to_b64(str);
	return (b64 != null) ? b64dec(b64) : null;
};

/**
 * Encodes a raw string to Base64URL.
 * 
 * @param {string} str - Raw binary string
 * @returns {string} - Base64URL string
 */
export function b64url_encode(str) {
	if (type(str) != "string") die("CONTRACT_VIOLATION: b64url_encode expects string");
	
	let b64 = b64enc(str);
	return _strip_padding(_map_to_url_safe(b64));
};

/**
 * Safely escapes a string for inclusion in HTML content.
 * Prevents XSS and JavaScript Unicode escape injection.
 * 
 * @param {string} str - Raw string
 * @returns {string} - HTML escaped string
 */
export function html_escape(str) {
	if (type(str) != "string") return "";
	let res = replace(str, /\\/g, "\\\\");
	res = replace(res, /&/g, "&amp;");
	res = replace(res, /</g, "&lt;");
	res = replace(res, />/g, "&gt;");
	res = replace(res, /"/g, "&quot;");
	res = replace(res, /'/g, "&#x27;");
	return res;
};

/**
 * Extracts exactly N bytes from a string.
 * This is byte-safe and avoids UTF-8 character boundary issues.
 * 
 * @param {string} data - Raw binary data string
 * @param {number} len - Number of bytes to extract
 * @returns {string} - Truncated binary string
 */
export function binary_truncate(data, len) {
	if (type(data) != "string") die("CONTRACT_VIOLATION: binary_truncate expects string data");
	if (type(len) != "int") die("CONTRACT_VIOLATION: binary_truncate expects integer length");

	let res = "";
	for (let i = 0; i < len; i++) {
		res += chr(ord(data, i));
	}
	return res;
};

/**
 * Pure JSON decoder that returns a Result Object.
 * Handles both strings and stream-like objects with a .read() method.
 * 
 * @param {string|object} data - Input to decode.
 * @returns {object} - { ok: true, data: ... } or { ok: false, error: "CODE", details: "..." }
 */
export function safe_json(data) {
	let raw = (type(data) == "object" && type(data.read) == "function") ? data.read() : data;
	if (type(raw) != "string") return Result.err("INVALID_TYPE");

	try {
		return Result.ok(json(raw));
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
 * @returns {string} - Normalized URL
 */
export function normalize_url(url) {
	if (type(url) != "string") return "";
	
	let res = url;
	let m = match(url, /^([A-Za-z]+:\/\/)([^/]+)(.*)$/);
	if (m) {
		res = lc(m[1]) + lc(m[2]) + m[3];
	}

	        // Remove trailing slashes
	        res = replace(res, /\/+$/, "");
	        return res;
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
