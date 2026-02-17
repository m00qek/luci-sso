'use strict';

import * as lucihttp from 'lucihttp';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';

/**
 * Maximum size for environment variables or parameter strings.
 */
const MAX_INPUT_LEN = 16384;

/**
 * Maximum number of parameters allowed to prevent memory exhaustion.
 */
const MAX_PARAM_COUNT = 100;

/**
 * Maps HTTP status codes to their standard reason phrases.
 * @private
 */
const HTTP_STATUS_MESSAGES = {
	"200": "200 OK",
	"302": "302 Found",
	"400": "400 Bad Request",
	"401": "401 Unauthorized",
	"403": "403 Forbidden",
	"404": "404 Not Found",
	"431": "431 Request Header Fields Too Large",
	"500": "500 Internal Server Error"
};

/**
 * Maps internal error codes to user-friendly messages.
 * @private
 */
const ERROR_MAP = {
	"STATE_NOT_FOUND": "Your session has expired or is invalid. You MUST try logging in again.",
	"STATE_CORRUPTED": "Authentication failed due to a system error. You MUST contact your administrator.",
	"STATE_SAVE_FAILED": "Internal server error: Could not initialize authentication. You MUST contact your administrator.",
	"OIDC_DISCOVERY_FAILED": "Could not connect to the Identity Provider. Contact your administrator.",
	"TOKEN_EXCHANGE_FAILED": "Failed to exchange authorization code for tokens. Contact your administrator.",
	"OIDC_INVALID_GRANT": "The authorization code is expired or has already been used. You MUST try logging in again.",
	"ID_TOKEN_VERIFICATION_FAILED": "The identity token provided by the IdP is invalid. You MUST contact your administrator.",
	"USER_NOT_AUTHORIZED": "Your account is not authorized to access this device. You MUST contact your administrator.",
	"AUTH_FAILED": "Authentication failed. You MUST try logging in again.",
	"NETWORK_ERROR": "A network error occurred while communicating with the IdP. Contact your administrator.",
	"INSECURE_ENDPOINT": "The IdP provided an insecure endpoint. Connection aborted for security. You MUST contact your administrator.",
	"INPUT_TOO_LARGE": "The request contains too much data. You MUST reduce the size of your request (e.g. fewer cookies)."
};

/**
 * Safely retrieves an environment variable with length enforcement.
 * @private
 */
function safe_getenv(io, key) {
	let val = io.getenv(key);
	if (val && length(val) > MAX_INPUT_LEN) return Result.err("INPUT_TOO_LARGE", { http_status: 431, key: key });
	return Result.ok(val);
}

/**
 * Parses a query string into an object with URL decoding.
 */
export function parse_params(str) {
	let params = {};
	if (!str || type(str) != "string") return Result.ok(params);
	if (length(str) > MAX_INPUT_LEN) return Result.err("INPUT_TOO_LARGE", { http_status: 431 });

	let pairs = split(str, "&");
	if (length(pairs) > MAX_PARAM_COUNT) return Result.err("INPUT_TOO_LARGE", { http_status: 431 });

	for (let pair in pairs) {
		let parts = split(pair, "=", 2);
		let k = parts[0];
		let v = parts[1];
		if (k) {
			let key = lucihttp.urldecode(replace(k, /\+/g, ' '));
			let val = (v != null) ? lucihttp.urldecode(replace(v, /\+/g, ' ')) : null;
			params[key] = val;
		}
	}
	return Result.ok(params);
};

/**
 * Parses a cookie header string into an object.
 */
export function parse_cookies(str) {
	let cookies = {};
	if (!str || type(str) != "string") return Result.ok(cookies);
	if (length(str) > MAX_INPUT_LEN) return Result.err("INPUT_TOO_LARGE", { http_status: 431 });

	let pairs = split(str, /;[ ]*/);
	if (length(pairs) > MAX_PARAM_COUNT) return Result.err("INPUT_TOO_LARGE", { http_status: 431 });

	for (let pair in pairs) {
		let trimmed = trim(pair);
		if (!length(trimmed)) continue;
		let parts = split(trimmed, "=", 2);
		let k = trim(parts[0]);
		let v = trim(parts[1] || "");
		if (length(v) >= 2 && substr(v, 0, 1) == '"' && substr(v, -1) == '"') {
			v = trim(substr(v, 1, length(v) - 2));
		}
		if (k) {
			cookies[k] = v;
		}
	}
	return Result.ok(cookies);
};

/**
 * Sanitizes a header value to prevent CRLF injection (HTTP Response Splitting).
 * @private
 */
function _sanitize_header(val) {
	if (type(val) != "string") return val;
	return replace(val, /[\r\n]+/g, " ");
}

/**
 * Internal helper to write HTTP headers and body.
 * @private
 */
function _out(io, headers, body) {
	// CGI SPEC: Status header MUST come first if present
	if (headers["Status"]) {
		io.stdout.write(`Status: ${_sanitize_header(headers["Status"])}\n`);
		delete headers["Status"];
	}

	for (let k, v in headers) {
		if (type(v) == "array") {
			for (let val in v) {
				io.stdout.write(`${k}: ${_sanitize_header(val)}\n`);
			}
		} else if (v != null) {
			io.stdout.write(`${k}: ${_sanitize_header(v)}\n`);
		}
	}
	io.stdout.write("\n");
	if (body != null) {
		io.stdout.write(body);
	}
	io.stdout.flush();
}

/**
 * Extracts and parses the request context from the CGI environment.
 * 
 * @param {object} io - I/O provider
 * @returns {object} - Result.ok({path, query, cookies, env}) or Result.err
 */
export function request(io) {
	let res_path = safe_getenv(io, "PATH_INFO");
	if (!res_path.ok) return res_path;

	let res_qs = safe_getenv(io, "QUERY_STRING");
	if (!res_qs.ok) return res_qs;

	let res_cookie = safe_getenv(io, "HTTP_COOKIE");
	if (!res_cookie.ok) return res_cookie;

	let res_host = safe_getenv(io, "HTTP_HOST");
	if (!res_host.ok) return res_host;

	let res_params = parse_params(res_qs.data);
	if (!res_params.ok) return res_params;

	let res_cookies = parse_cookies(res_cookie.data);
	if (!res_cookies.ok) return res_cookies;

	let path = res_path.data;
	if (path == null) path = "/";

	return Result.ok({
		path: path,
		query: res_params.data,
		cookies: res_cookies.data,
		env: {
			HTTP_HOST: res_host.data
		}
	});
};

/**
 * Formats and sends the HTTP response to stdout.
 * 
 * @param {object} io - I/O provider
 * @param {object} res - Response object {status, headers, body}
 */
export function render(io, res) {
	let headers = res.headers || {};
	let body = res.body || "";

	// Defense-in-Depth: Strict Content Security Policy
	headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'none';";
	headers["X-Content-Type-Options"] = "nosniff";
	headers["X-Frame-Options"] = "DENY";
	headers["Cache-Control"] = "no-store";
	headers["Referrer-Policy"] = "no-referrer";

	headers["Status"] = HTTP_STATUS_MESSAGES["" + res.status] || HTTP_STATUS_MESSAGES["200"];

	if (res.status == 302) {
		headers["Content-Type"] = "text/html";
		body = '<html><body><p>Redirecting...</p></body></html>\n';
	}

	_out(io, headers, body);
};

/**
 * Standardizes and renders an error response, preventing internal leakage.
 * 
 * @param {object} io - I/O provider
 * @param {string} code - Internal error code (SCREAMING_SNAKE_CASE)
 * @param {number} status - HTTP status code
 */
export function render_error(io, code, status) {
	let user_msg = ERROR_MAP[code] || "An unexpected authentication error occurred.";

	io.log("error", `[${status || 500}] ${code}`);

	_out(io, {
		"Status": HTTP_STATUS_MESSAGES["" + (status || 500)] || "500 Internal Server Error",
		"Content-Type": "text/plain"
	}, `Error: ${user_msg}\n`);
};

/**
 * Handles fatal script errors and crashes.
 * 
 * @param {object} io - I/O provider
 * @param {any} e - The error object or message
 */
export function error(io, e) {
	let msg = sprintf("%s", e);
	let stack = (type(e) == "object") ? e.stacktrace : "";

	io.log("error", `Router crash: ${msg}\n${stack}`);

	_out(io, {
		"Status": "500 Internal Server Error",
		"Content-Type": "text/plain"
	}, "Router Crash: An internal error occurred. Please contact support.\n");
};
