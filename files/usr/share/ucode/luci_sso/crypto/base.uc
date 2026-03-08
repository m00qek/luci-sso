import * as Result from 'luci_sso.result';

/**
 * Constant-time string comparison to prevent timing attacks.
 * 
 * This implementation avoids early returns on length mismatch or content
 * difference to mitigate timing side-channels.
 * 
 * NOTE: True constant-time execution is impossible in an interpreted runtime 
 * like ucode due to GC, hash-table-backed strings, and variable-time ord().
 * This function provides a best-effort mitigation by using the XOR-accumulator 
 * pattern and avoiding logical branching based on secret content.
 */
export function constant_time_eq(a, b) {
	if (type(a) != "string" || type(b) != "string") return false;

	let len_a = length(a);
	let len_b = length(b);

	// MANDATORY: Length cap to prevent DoS via amplification (W1)
	// Any value longer than 16KB is considered excessive for tokens/hashes in this system.
	if (len_a > 16384 || len_b > 16384) return false;

	let res = (len_a ^ len_b);

	// We iterate based on the maximum length of the two strings.
	// This ensures that for any two inputs, the timing is dominated by the
	// longer string, mitigating length-probing attacks.
	let max_len = (len_a > len_b) ? len_a : len_b;
	for (let i = 0; i < max_len; i++) {
		let char_a = ord(a, i % (len_a || 1));
		let char_b = ord(b, i % (len_b || 1));
		res |= (char_a ^ char_b);
	}

	return (res == 0);
};

/**
 * Generates cryptographically secure random bytes.
 * 
 * @param {object} io - I/O provider
 * @param {number} [len=32] - Number of bytes to generate
 * @returns {object} - Result Object {ok, data/error}
 */
export function random(native, len) {
	let byte_len = len || 32;
	if (type(byte_len) != "int")
    die("CONTRACT_VIOLATION: random expects integer length");

	let bytes = native.random(byte_len);
	if (!bytes || type(bytes) != "string" || length(bytes) != byte_len) {
		return Result.err("CSPRNG_FAILURE");
	}

	return Result.ok(bytes);
};

/**
 * Converts a sensitive token or handle into a safe, redacted correlation ID.
 * Uses the first 16 hex characters (64 bits) of the SHA256 hash.
 * 
 * NOTE: This 64-bit truncation provides a birthday collision bound of ~2^32.
 * This is considered acceptable for correlation IDs in router logs, but MUST
 * NOT be used for cryptographic identity or primary key indexing where
 * collisions could lead to security vulnerabilities.
 * 
 * @param {string} token - The sensitive token or handle.
 * @returns {string} - The 16-character safe ID, or '[INVALID]'.
 */
export function safe_id(native, token) {
	if (!token || type(token) != "string" || length(token) < 8)
		return "[INVALID]";

	let hash_bin = native.sha256(token);
	if (!hash_bin)
    return "[ERROR]";

	let hex = "";
	for (let i = 0; i < 8; i++) {
		hex += sprintf("%02x", ord(hash_bin, i));
	}

	return hex;
};
