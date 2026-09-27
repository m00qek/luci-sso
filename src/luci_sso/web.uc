"use strict";

import * as lucihttp from 'lucihttp';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import { INPUT_TOO_LARGE } from 'luci_sso.errors';

/**
 * Maximum size for environment variables or parameter strings.
 */
const LIMIT_INPUT_LEN = 16384;

/**
 * Maximum number of parameters allowed to prevent memory exhaustion.
 */
const LIMIT_PARAM_COUNT = 100;

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
	"429": "429 Too Many Requests",
	"431": "431 Request Header Fields Too Large",
	"500": "500 Internal Server Error",
	"503": "503 Service Unavailable"
};

/**
 * Maps internal error codes to user-friendly messages.
 * @private
 */
const ERROR_MAP = {
	"STATE_NOT_FOUND": "Your sign-in attempt expired or was already used. Please try signing in again.",
	"STATE_CORRUPTED": "Sign-in failed because of a problem on this router. Please contact your administrator.",
	"STATE_SAVE_FAILED": "Sign-in could not start because of a problem on this router. Please contact your administrator.",
	"OIDC_DISCOVERY_FAILED": "The router could not reach the identity provider. Please try again later, or contact your administrator.",
	"TOKEN_EXCHANGE_FAILED": "The identity provider did not accept the sign-in request. Please contact your administrator.",
	"OIDC_INVALID_GRANT": "This sign-in attempt expired or was already used. Please try signing in again.",
	"ID_TOKEN_VERIFICATION_FAILED": "The identity provider's response could not be verified. Please contact your administrator.",
	"USER_NOT_AUTHORIZED": "Your account is not allowed to manage this router. Please contact your administrator if you need access.",
	"TOKEN_REPLAYED": "This sign-in response was already used. Please try signing in again.",
	"TOKEN_REGISTRY_ERROR": "Sign-in failed because of a problem on this router. Please contact your administrator.",
	"CSRF_CHECK_FAILED": "This logout link is invalid or has expired, so nothing was changed.",
	"TOKEN_ENDPOINT_NETWORK_ERROR": "The router could not reach the identity provider. Please try again later, or contact your administrator.",
	"INSECURE_ENDPOINT": "Sign-in was stopped because the identity provider is not configured securely. Please contact your administrator.",
	"INPUT_TOO_LARGE": "The request contained too much data. Clearing this site's cookies usually fixes this.",
	"HANDSHAKE_CAPACITY_EXCEEDED": "Too many sign-ins are in progress right now. Please try again in a few minutes, or log in with a password.",
	"TOO_MANY_REQUESTS": "There have been too many sign-in attempts. Please wait a minute and try again.",
	"SSO_DISABLED": "Single sign-on is not enabled on this router. You can still log in with a password.",
	"NOT_FOUND": "This page does not exist."
};

/**
 * Shown for any code without a specific message, and for crashes.
 * @private
 */
const GENERIC_MESSAGE = "Sign-in could not be completed. Please try again, or contact your administrator.";

/**
 * Where the error page's link sends the user: LuCI's own login page, which
 * also carries the SSO button.
 * @private
 */
const LOGIN_URL = "/cgi-bin/luci/";

/**
 * Renders the body of an error page: a heading, one message and a link back
 * to the login page. No inline style or script, so the page satisfies the
 * default-src 'none' CSP applied to every response. The message is always one
 * of the fixed strings above, never request data or an internal error code.
 * @private
 */
function _error_page(message) {
	return "<!DOCTYPE html>\n" +
		'<html lang="en">\n' +
		'<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Single sign-on</title></head>\n' +
		"<body>\n" +
		"<h1>Single sign-on</h1>\n" +
		`<p>${message}</p>\n` +
		`<p><a href="${LOGIN_URL}">Back to the login page</a></p>\n` +
		"</body>\n" +
		"</html>\n";
}

/**
 * Safely retrieves an environment variable with length enforcement.
 * @private
 */
function safe_getenv(getenv, key) {
	let val = getenv(key);
	if (val && length(val) > LIMIT_INPUT_LEN) return Result.err(INPUT_TOO_LARGE, { http_status: 431, key: key });
	return Result.ok(val);
}

/**
 * Parses a query string into an object with URL decoding.
 */
export function parse_params(str) {
	let params = {};
	if (!str || type(str) != "string") return Result.ok(params);
	if (length(str) > LIMIT_INPUT_LEN) return Result.err(INPUT_TOO_LARGE, { http_status: 431 });

	let pairs = split(str, "&");
	if (length(pairs) > LIMIT_PARAM_COUNT) return Result.err(INPUT_TOO_LARGE, { http_status: 431 });

	for (let pair in pairs) {
		let parts = split(pair, "=", 2);
		let k = parts[0];
		let v = parts[1];
		if (k) {
			let key = lucihttp.urldecode(replace(k, /\+/g, " "));
			let val = (v != null) ? lucihttp.urldecode(replace(v, /\+/g, " ")) : null;
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
	if (length(str) > LIMIT_INPUT_LEN) return Result.err(INPUT_TOO_LARGE, { http_status: 431 });

	let pairs = split(str, /;[ ]*/);
	if (length(pairs) > LIMIT_PARAM_COUNT) return Result.err(INPUT_TOO_LARGE, { http_status: 431 });

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
function _out(stdout, headers, body) {
	// CGI SPEC: Status header MUST come first if present
	if (headers["Status"]) {
		stdout.write(`Status: ${_sanitize_header(headers["Status"])}\n`);
		delete headers["Status"];
	}

	for (let k, v in headers) {
		if (type(v) == "array") {
			for (let val in v) {
				stdout.write(`${k}: ${_sanitize_header(val)}\n`);
			}
		} else if (v != null) {
			stdout.write(`${k}: ${_sanitize_header(v)}\n`);
		}
	}
	stdout.write("\n");
	if (body != null) {
		stdout.write(body);
	}
	stdout.flush();
}

/**
 * Applies security headers to a response headers object in-place.
 * MUST be called for every response — success, error, and crash alike.
 * @private
 */
function _apply_security_headers(headers) {
	headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; frame-ancestors 'none';";
	headers["X-Content-Type-Options"] = "nosniff";
	headers["X-Frame-Options"] = "DENY";
	headers["Cache-Control"] = "no-store";
	headers["Referrer-Policy"] = "no-referrer";
}

/**
 * Extracts and parses the request context from the CGI environment.
 *
 * @param {object} deps - { getenv }
 * @returns {object} - Result.ok({path, query, cookies, client}) or Result.err
 */
export function request(deps) {
	let res_path = safe_getenv(deps.getenv, "PATH_INFO");
	if (!res_path.ok) return res_path;

	let res_qs = safe_getenv(deps.getenv, "QUERY_STRING");
	if (!res_qs.ok) return res_qs;

	let res_cookie = safe_getenv(deps.getenv, "HTTP_COOKIE");
	if (!res_cookie.ok) return res_cookie;

	// The client address uhttpd saw, used only as a rate-limit key.
	let res_addr = safe_getenv(deps.getenv, "REMOTE_ADDR");
	if (!res_addr.ok) return res_addr;

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
		client: res_addr.data
	});
};

/**
 * Formats and sends the HTTP response to stdout.
 *
 * @param {object} deps - { stdout }
 * @param {object} res - Response object {status, headers, body}
 */
export function render(deps, res) {
	let headers = res.headers || {};
	let body = res.body || "";

	_apply_security_headers(headers);

	headers["Status"] = HTTP_STATUS_MESSAGES["" + res.status] || HTTP_STATUS_MESSAGES["200"];

	if (res.status == 302) {
		headers["Content-Type"] = "text/html";
		body = "<html><body><p>Redirecting...</p></body></html>\n";
	}

	_out(deps.stdout, headers, body);
};

/**
 * Standardizes and renders an error response, preventing internal leakage.
 *
 * @param {object} deps - { log, stdout }
 * @param {string} code - Internal error code (SCREAMING_SNAKE_CASE)
 * @param {number} status - HTTP status code
 * @param {object} [extra] - Additional response headers, e.g. { "Retry-After": "42" }
 */
export function render_error(deps, code, status, extra) {
	let user_msg = ERROR_MAP[code] || GENERIC_MESSAGE;

	deps.log("error", `[${status || 500}] ${code}`);

	let headers = {
		"Status": HTTP_STATUS_MESSAGES["" + (status || 500)] || "500 Internal Server Error",
		"Content-Type": "text/html; charset=utf-8"
	};
	for (let k, v in (extra || {}))
		headers[k] = v;
	_apply_security_headers(headers);
	_out(deps.stdout, headers, _error_page(user_msg));
};

/**
 * Handles fatal script errors and crashes.
 *
 * @param {object} deps - { log, stdout }
 * @param {any} e - The error object or message
 */
export function error(deps, e) {
	let msg = sprintf("%s", e);
	let stack = (type(e) == "object") ? e.stacktrace : "";

	deps.log("error", `Router crash: ${msg}\n${stack}`);

	let headers = {
		"Status": "500 Internal Server Error",
		"Content-Type": "text/html; charset=utf-8"
	};
	_apply_security_headers(headers);
	_out(deps.stdout, headers, _error_page(GENERIC_MESSAGE));
};
