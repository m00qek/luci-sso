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
	for (let pair in split(str, ";")) {
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
 * @returns {object} - {path, query, cookies}
 */
export function request(io) {
	if (!io || type(io.getenv) != "function") {
		die("CONTRACT_VIOLATION: web.request expects an IO provider with getenv");
	}

	return {
		path: safe_getenv(io, "PATH_INFO") || "/",
		query: parse_params(safe_getenv(io, "QUERY_STRING")),
		cookies: parse_cookies(safe_getenv(io, "HTTP_COOKIE"))
	};
};

/**
 * Formats and sends the HTTP response to stdout.
 * 
 * @param {object} io - I/O provider
 * @param {object} res - Response object {status, headers, body}
 */
export function render(io, res) {
	if (!io || !io.stdout || type(io.stdout.write) != "function" || type(io.stdout.flush) != "function") {
		die("CONTRACT_VIOLATION: web.render expects an IO provider with a writable stdout");
	}

	let headers = res.headers || {};
	let body = res.body || "";

	if (res.status == 302) {
		headers["Status"] = "302 Found";
		headers["Content-Type"] = "text/html";
		
		let loc = headers["Location"] || "";
		body = '<html><head><script>window.location.href="' + loc + '";</script></head>';
		body += '<body><p>Redirecting to <a href="' + loc + '">' + loc + '</a>...</p></body></html>\n';
	} else {
		if (res.status != 200) {
			headers["Status"] = res.status;
		}
	}

	_out(io, headers, body);
};

/**
 * Handles fatal script errors and crashes.
 * 
 * @param {object} io - I/O provider
 * @param {any} e - The error object or message
 */
export function error(io, e) {
	if (!io || !io.stdout || type(io.stdout.write) != "function" || type(io.stdout.flush) != "function") {
		die("CONTRACT_VIOLATION: web.error expects an IO provider with a writable stdout");
	}

	let msg = sprintf("%s", e);
	let stack = (type(e) == "object") ? e.stacktrace : "";
	
	warn(`[luci-sso] Router crash: ${msg}\n${stack}\n`);
	
	_out(io, {
		"Status": "500 Internal Server Error",
		"Content-Type": "text/plain"
	}, "Router Crash: " + msg + "\n");
};
