'use strict';

import * as lucihttp from 'lucihttp';

/**
 * Maximum size for environment variables or parameter strings.
 */
const MAX_INPUT_LEN = 16384;

/**
 * Maximum number of parameters allowed to prevent memory exhaustion.
 */
const MAX_PARAM_COUNT = 100;

/**
 * Safely retrieves an environment variable with length enforcement.
 * @private
 */
function safe_getenv(io, key) {
	let val = io.getenv(key);
	if (val && length(val) > MAX_INPUT_LEN) return null;
	return val;
}

/**
 * Parses a query string into an object with URL decoding.
 */
export function parse_params(str) {
	let params = {};
	if (!str || type(str) != "string") return params;
	if (length(str) > MAX_INPUT_LEN) return params;

	let count = 0;
	for (let pair in split(str, "&")) {
		if (count >= MAX_PARAM_COUNT) break;
		let parts = split(pair, "=", 2);
		let k = parts[0];
		let v = parts[1];
		if (k) {
			let key = lucihttp.urldecode(replace(k, /\+/g, ' '));
			let val = (v != null) ? lucihttp.urldecode(replace(v, /\+/g, ' ')) : null;
			params[key] = val;
			count++;
		}
	}
	return params;
};

/**
 * Parses a cookie header string into an object.
 */
export function parse_cookies(str) {
	let cookies = {};
	if (!str || type(str) != "string") return cookies;
	if (length(str) > MAX_INPUT_LEN) return cookies;

	let count = 0;
	// RFC 6265: Cookies are separated by semicolon and a space "; "
	for (let pair in split(str, /;[ ]*/)) {
		if (count >= MAX_PARAM_COUNT) break;
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
			count++;
		}
	}
	return cookies;
};

/**
 * Internal helper to write HTTP headers and body.
 * @private
 */
function _out(io, headers, body) {
	// CGI SPEC: Status header MUST come first if present
	if (headers["Status"]) {
		io.stdout.write(`Status: ${headers["Status"]}\n`);
		delete headers["Status"];
	}

	for (let k, v in headers) {
		if (type(v) == "array") {
			for (let val in v) {
				io.stdout.write(`${k}: ${val}\n`);
			}
		} else if (v != null) {
			io.stdout.write(`${k}: ${v}\n`);
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
 * @returns {object} - {path, query, cookies, env}
 */
export function request(io) {
	return {
		path: safe_getenv(io, "PATH_INFO") || "/",
		query: parse_params(safe_getenv(io, "QUERY_STRING")),
		cookies: parse_cookies(safe_getenv(io, "HTTP_COOKIE")),
		env: {
			HTTP_HOST: safe_getenv(io, "HTTP_HOST")
		}
	};
};

/**
 * Safely escapes a string for inclusion in HTML content.
 * @private
 */
function html_escape(str) {
	if (type(str) != "string") return "";
	let res = replace(str, /\\/g, "\\\\");
	res = replace(res, /&/g, "&amp;");
	res = replace(res, /</g, "&lt;");
	res = replace(res, />/g, "&gt;");
	res = replace(res, /"/g, "&quot;");
	res = replace(res, /'/g, "&#x27;");
	return res;
}

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

	if (res.status == 302) {
		headers["Status"] = "302 Found";
		headers["Content-Type"] = "text/html";
		
		let loc = headers["Location"] || "";
		let escaped_loc = html_escape(loc);
		body = '<html><head><meta http-equiv="refresh" content="0;url=' + escaped_loc + '"></head>';
		body += '<body><p>Redirecting to <a href="' + escaped_loc + '">' + escaped_loc + '</a>...</p></body></html>\n';
	} else if (res.status == 401) {
		headers["Status"] = "401 Unauthorized";
	} else if (res.status == 403) {
		headers["Status"] = "403 Forbidden";
	} else if (res.status == 404) {
		headers["Status"] = "404 Not Found";
	} else if (res.status >= 500) {
		headers["Status"] = "500 Internal Server Error";
	} else {
		headers["Status"] = "200 OK";
	}

	_out(io, headers, body);
};

/**
 * Maps internal error codes to user-friendly messages.
 * @private
 */
const ERROR_MAP = {
	"STATE_NOT_FOUND": "Your session has expired or is invalid. Please try logging in again.",
	"STATE_CORRUPTED": "Authentication failed due to a system error. Please try again.",
	"STATE_SAVE_FAILED": "Internal server error: Could not initialize authentication.",
	"OIDC_DISCOVERY_FAILED": "Could not connect to the Identity Provider.",
	"TOKEN_EXCHANGE_FAILED": "Failed to exchange authorization code for tokens.",
	"OIDC_INVALID_GRANT": "The authorization code is expired or has already been used. Please try logging in again.",
	"ID_TOKEN_VERIFICATION_FAILED": "The identity token provided by the IdP is invalid.",
	"USER_NOT_AUTHORIZED": "Your account is not authorized to access this device.",
	"AUTH_FAILED": "Authentication failed. Please try logging in again.",
	"NETWORK_ERROR": "A network error occurred while communicating with the IdP.",
	"INSECURE_ENDPOINT": "The IdP provided an insecure endpoint. Connection aborted for security."
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
		"Status": status || 500,
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
