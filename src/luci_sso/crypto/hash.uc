import * as Result from 'luci_sso.result';

/**
 * Calculates SHA256 hash.
 * 
 * @param {module:luci_sso.native} native Compiled crypto extension; `native.sha256()` computes the digest.
 * @param {string} str Data to hash.
 * @returns {Result}
 */
export function sha256(native, str) {
	if (type(str) != "string")
		 return Result.err("INVALID_ARGUMENT", "hash_sha256 expects string input");

	let hash = native.sha256(str);
	if (!hash)
		 return Result.err("CRYPTO_ERROR");

	return Result.ok(hash);
};

/**
 * Calculates SHA256 hash and returns it as a 64-character hex digest.
 * 
 * @param {module:luci_sso.native} native Compiled crypto extension; `native.sha256()` computes the digest.
 * @param {string} str Data to hash.
 * @returns {Result}
 */
export function sha256_hex(native, str) {
	let res = sha256(native, str);
	if (!res.ok)
		 return res;

	let hash_bin = res.data;
	let hex = "";
	for (let i = 0; i < length(hash_bin); i++) {
		hex += sprintf("%02x", ord(hash_bin, i));
	}
	return Result.ok(hex);
};
