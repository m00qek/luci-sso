/**
 * Maximum length allowed for a parameter string (Query or Cookie).
 */
const MAX_INPUT_LEN = 16384;

/**
 * Maximum number of parameters allowed to prevent memory exhaustion.
 */
const MAX_PARAM_COUNT = 100;

/**
 * Parses a query string or cookie string into an object.
 * 
 * @param {string} str - The string to parse
 * @param {string} [sep="&"] - The separator character
 * @returns {object} - Key-value pairs
 */
export function parse_params(str, sep) {
	let params = {};
	if (!str || type(str) != "string") return params;
	
	// Guard 1: Total length limit
	if (length(str) > MAX_INPUT_LEN) {
		return params; // Fail safe with empty object
	}

	let count = 0;
	for (let pair in split(str, sep || "&")) {
		// Guard 2: Parameter count limit
		if (count >= MAX_PARAM_COUNT) break;

		let parts = split(trim(pair), "=", 2);
		let k = parts[0];
		let v = parts[1];
		if (k) {
			params[k] = v;
			count++;
		}
	}
	return params;
};