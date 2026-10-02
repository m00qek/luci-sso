"use strict";

import * as Result from 'luci_sso.result';
import { INVALID_ARGUMENT, TOKEN_TOO_LARGE } from 'luci_sso.errors';

/**
 * Implementation of RFC 7515 Base64URL encoding and decoding.
 */

const MAX_UTILS_SIZE = 32768; // 32 KB

/**
 * Maps standard Base64 characters to URL-safe ones.
 * @private
 */
function _map_to_url_safe(str) {
	let res = replace(str, /\+/g, "-");
	return replace(res, /\//g, "_");
}

/**
 * Maps URL-safe characters back to standard Base64.
 * @private
 */
function _map_from_url_safe(str) {
	let res = replace(str, /-/g, "+");
	return replace(res, /_/g, "/");
}

/**
 * Adds padding characters to a Base64 string if needed.
 * @private
 */
function _add_padding(str) {
	let pad = (4 - (length(str) % 4)) % 4;
	for (let i = 0; i < pad; i++) {
		str += "=";
	}
	return str;
}

/**
 * Removes all padding characters from a Base64 string.
 * @private
 */
function _strip_padding(str) {
	return replace(str, /=/g, "");
}

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
}

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
		return Result.err(TOKEN_TOO_LARGE);

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
		return Result.err("BASE64URL_ENCODE_FAILED");

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
 * Normalizes a URL: lowercases the scheme and host, drops the default port
 * and removes trailing slashes. Per RFC 3986, the path is case-sensitive.
 *
 * Never use it to compare an issuer identifier: OIDC compares issuers as
 * exact strings (Core §3.1.3.7, Discovery §4.3). It only builds cache keys
 * and diagnostic hints.
 * 
 * @param {string} url - The URL to normalize
 * @returns {object} - Result Object {ok, data/error}
 */
export function normalize_url(url) {
	if (type(url) != "string")
		return Result.err(INVALID_ARGUMENT, "normalize_url expects string");
	
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
 * Splits an absolute URL into its origin and the rest.
 *
 * The origin is normalised for comparison: scheme and host lowercased, and
 * the default port (443 for https, 80 for http) dropped. The rest (path,
 * query and fragment) is returned verbatim. URLs with userinfo
 * (user@host) are refused.
 *
 * @param {string} url
 * @returns {object} - Result.ok({ origin, rest }) or Result.err
 */
export function split_origin(url) {
	if (type(url) != "string")
		return Result.err("INVALID_ARGUMENT", "split_origin expects string");

	let m = match(url, /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^\/?#]+)(.*)$/);
	if (!m || index(m[2], "@") >= 0)
		return Result.err("MALFORMED_URL", "not an absolute URL with a host");

	let scheme = lc(m[1]);
	let authority = lc(m[2]);
	if (scheme == "https")
		authority = replace(authority, /:443$/, "");
	else if (scheme == "http")
		authority = replace(authority, /:80$/, "");

	return Result.ok({ origin: `${scheme}://${authority}`, rest: m[3] });
};

/**
 * True if `url` is a bare origin: scheme://host[:port], optionally with a
 * single trailing "/", and no path, query or fragment.
 *
 * @param {string} url
 * @returns {boolean}
 */
export function is_origin(url) {
	let res = split_origin(url);
	return res.ok && (res.data.rest == "" || res.data.rest == "/");
};

/**
 * Moves `url` from one origin to another. If `url`'s origin equals
 * `from`'s origin, returns `to`'s origin followed by `url`'s path, query and
 * fragment, unchanged. Otherwise, or if any argument is not a URL, returns
 * `url` untouched.
 *
 * @param {string} url
 * @param {string} from - A URL whose origin is being replaced (its path is ignored).
 * @param {string} to - A URL whose origin replaces it (its path is ignored).
 * @returns {string}
 */
export function rebase_origin(url, from, to) {
	let u = split_origin(url), f = split_origin(from), t = split_origin(to);
	if (!u.ok || !f.ok || !t.ok) return url;
	if (u.data.origin != f.data.origin || f.data.origin == t.data.origin) return url;
	return t.data.origin + u.data.rest;
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

const LOG_VALUE_MAX = 200;

/**
 * Makes an untrusted value safe to put in a log line.
 *
 * Every byte outside printable ASCII (CR, LF, tabs, escape sequences, and
 * non-ASCII bytes) becomes "?", so a value cannot forge extra log lines or
 * terminal control codes. The result is capped at `max` bytes (default 200)
 * and ends in "..." when it was cut. A non-string yields "".
 *
 * @param {*} value - Value to sanitise, typically a request or IdP field
 * @param {number} [max] - Maximum length kept before truncation
 * @returns {string}
 */
export function log_safe(value, max) {
	if (type(value) != "string") return "";
	let limit = (type(max) == "int" && max > 0) ? max : LOG_VALUE_MAX;
	let clean = replace(value, /[^ -~]/g, "?");
	if (length(clean) > limit) clean = substr(clean, 0, limit) + "...";
	return clean;
};

/**
 * Longest `return_to` path accepted, in bytes.
 * @private
 */
const LIMIT_RETURN_PATH_LEN = 512;

/**
 * Percent-decoding rounds tried before a value is refused as nested encoding.
 * @private
 */
const RETURN_PATH_DECODE_PASSES = 3;

/**
 * The punctuation a `return_to` path may hold, as byte values:
 * / _ . ~ % ? & = + , -
 * @private
 */
const RETURN_PATH_PUNCT = [ 47, 95, 46, 126, 37, 63, 38, 61, 43, 44, 45 ];

/**
 * LuCI's own logout page. Returning there, or to any path under it, would end
 * the session just created: LuCI's dispatcher runs the deepest node it can
 * match and ignores the segments after it, so /cgi-bin/luci/admin/logout/x
 * runs the logout too.
 * @private
 */
const LUCI_LOGOUT_PATH = "/cgi-bin/luci/admin/logout";

/**
 * True when every byte of `s` is a letter, a digit or RETURN_PATH_PUNCT.
 * Checked byte by byte, not with a regex, so an embedded NUL cannot end the
 * check early.
 * @private
 */
function _return_path_bytes_ok(s) {
	for (let i = 0; i < length(s); i++) {
		let c = ord(s, i);
		if ((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122))
			continue;
		if (index(RETURN_PATH_PUNCT, c) < 0)
			return false;
	}
	return true;
}

/**
 * Checks one form (as sent, or decoded) of a `return_to` path: the path part
 * must be LuCI's (/cgi-bin/luci, or under /cgi-bin/luci/), with no "//"
 * anywhere and no "." or ".." segment. Returns the reason it fails, or null.
 * @private
 */
function _return_path_shape(path, whole) {
	if (path != "/cgi-bin/luci" && substr(path, 0, 14) != "/cgi-bin/luci/")
		return "not a LuCI page";
	if (index(whole, "//") >= 0)
		return "contains //";
	for (let seg in split(path, "/")) {
		if (seg == "." || seg == "..")
			return "contains a dot segment";
	}
	if (path == LUCI_LOGOUT_PATH || substr(path, 0, length(LUCI_LOGOUT_PATH) + 1) == LUCI_LOGOUT_PATH + "/")
		return "is LuCI's logout page";
	return null;
}

/**
 * Decodes every %XX escape of `s` once. Returns null when a "%" does not
 * start a two-digit hexadecimal escape.
 * @private
 */
function _percent_decode(s) {
	if (index(replace(s, /%[0-9A-Fa-f][0-9A-Fa-f]/g, ""), "%") >= 0)
		return null;
	return replace(s, /%([0-9A-Fa-f][0-9A-Fa-f])/g, (m, h) => chr(hex(h)));
}

/**
 * Checks a page to return to after login (the `return_to` parameter).
 *
 * Accepts only a relative path to a LuCI page, so that the redirect can
 * never leave the router or reach another endpoint. The value must:
 *
 * - be a string of 1 to 512 bytes;
 * - hold only letters, digits and / _ . ~ % ? & = + , - (no scheme, no
 *   backslash, no "@", no control or non-ASCII bytes, no "#");
 * - have a path part (before the first "?") that is /cgi-bin/luci or starts
 *   with /cgi-bin/luci/, has no "." or ".." segment, and is neither LuCI's
 *   logout page nor a path under it; and contain no "//" anywhere.
 *
 * Every "%" must start a %XX escape. The value is then decoded, up to three
 * times, until no escape is left; each decoded form must pass the same
 * checks, so %2F%2F, %5C, %0D%0A, %2E%2E and double encoding are refused
 * too. More than three levels of encoding are refused. Dot segments are
 * refused, not resolved.
 *
 * @param {*} value - The untrusted value, as decoded once from the query string
 * @returns {object} - Result.ok(value unchanged) or Result.err("INVALID_RETURN_PATH", reason)
 */
export function return_path(value) {
	let bad = (reason) => Result.err("INVALID_RETURN_PATH", reason);

	if (type(value) != "string")
		return bad("not a string");
	if (!length(value))
		return bad("empty");
	if (length(value) > LIMIT_RETURN_PATH_LEN)
		return bad(`longer than ${LIMIT_RETURN_PATH_LEN} bytes`);

	// The path and the query are told apart by the first literal "?" of the
	// value as sent: a decoded %3F is part of the path, as the browser sees it.
	let q = index(value, "?");
	let path = (q < 0) ? value : substr(value, 0, q);
	let whole = value;

	for (let pass = 0; ; pass++) {
		if (!_return_path_bytes_ok(whole))
			return bad("holds a character outside the allowed set");
		let reason = _return_path_shape(path, whole);
		if (reason)
			return bad(reason);
		if (index(whole, "%") < 0)
			break;
		if (pass == RETURN_PATH_DECODE_PASSES)
			return bad("percent-encoded too many times");
		whole = _percent_decode(whole);
		path = _percent_decode(path);
		if (whole == null || path == null)
			return bad("has a malformed percent escape");
	}

	return Result.ok(value);
};
