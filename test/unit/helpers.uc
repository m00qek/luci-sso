import * as crypto from 'luci_sso.crypto';

/**
 * Generates a signed HS256 ID Token for Tier 2 business logic testing.
 * 
 * @param {object} payload - Claims to include in the token.
 * @param {string} secret - Symmetric secret for signing.
 * @returns {string} - Compact JWS string.
 */
export function generate_id_token(payload, secret) {
	return crypto.sign_jws(payload, secret);
};