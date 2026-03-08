import * as Result from 'luci_sso.result';

/**
 * Calculates SHA256 hash.
 * 
 * @param {string} str - Data to hash
 * @returns {string} - 32-byte binary hash string
 */
export function hash_sha256(native, str) {
	if (type(str) != "string")
    die("CONTRACT_VIOLATION: hash_sha256 expects string input");

	return native.sha256(str);
};

/**
 * Calculates SHA256 hash and returns it as a 64-character hex digest.
 * 
 * @param {string} str - Data to hash
 * @returns {object} - Result Object {ok, data/error}
 */
export function hash_sha256_hex(native, str) {
	let hash_bin = hash_sha256(native, str);
	if (!hash_bin)
    return Result.err("CRYPTO_ERROR");

	let hex = "";
	for (let i = 0; i < length(hash_bin); i++) {
		hex += sprintf("%02x", ord(hash_bin, i));
	}
	return Result.ok(hex);
};
