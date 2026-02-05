/**
 * Parses a query string or cookie string into an object.
 * 
 * @param {string} str - The string to parse
 * @param {string} [sep="&"] - The separator character
 * @returns {object} - Key-value pairs
 */
export function parse_params(str, sep) {
	let params = {};
	if (!str) return params;
	for (let pair in split(str, sep || "&")) {
		let parts = split(trim(pair), "=", 2);
		let k = parts[0];
		let v = parts[1];
		if (k) params[k] = v;
	}
	return params;
};
