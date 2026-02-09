import * as crypto from 'luci_sso.crypto';

/**
 * Logic utilities for luci-sso.
 */

/**
 * Converts a sensitive token or handle into a safe, redacted correlation ID.
 * Uses the first 8 hex characters of the SHA256 hash.
 * 
 * @param {string} token - The sensitive token or handle.
 * @returns {string} - The 8-character safe ID, or '[INVALID]'.
 */
export function safe_id(token) {
	if (!token || type(token) != "string" || length(token) < 8) {
		return "[INVALID]";
	}
	
	let hash_bin = crypto.sha256(token);
	if (!hash_bin) return "[ERROR]";
	
	let hex = "";
	for (let i = 0; i < 4; i++) {
		hex += sprintf("%02x", ord(hash_bin, i));
	}
	
	return hex;
};