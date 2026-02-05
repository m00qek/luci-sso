import * as lucihttp from 'lucihttp';

/**
 * Maximum length allowed for a parameter string (Query or Cookie).
 */
const MAX_INPUT_LEN = 16384;

/**
 * Maximum number of parameters allowed to prevent memory exhaustion.
 */
const MAX_PARAM_COUNT = 100;

/**
 * Parses a query string into an object with URL decoding.
 * 
 * @param {string} str - The string to parse
 * @returns {object} - Key-value pairs
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
			// RFC 1866: + should be treated as space in query strings
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
 * Handles quoted values and whitespace trimming.
 * 
 * @param {string} str - The cookie string
 * @returns {object} - Key-value pairs
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

		// Remove quotes if present
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
