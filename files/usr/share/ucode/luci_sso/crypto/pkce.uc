import * as Result from 'luci_sso.result';
import * as encoding from 'luci_sso.encoding';

import * as base from 'luci_sso.crypto.base';
import * as hash from 'luci_sso.crypto.hash';


/**
 * Generates a PKCE Code Verifier.
 * 
 * @param {object} io - I/O provider
 * @param {number} [len=43] - Length of verifier
 * @returns {object} - Result Object {ok, data/error}
 */
export function generate_verifier(native, len) {
  // TODO: use constants isntead of magic numbers
	let byte_len = len || 43;
	if (byte_len < 32 || byte_len > 96)
    die("CONTRACT_VIOLATION: PKCE verifier must be 32-96 bytes");

	let res = base.random(native, byte_len);
	if (!res.ok)
    return res;

	return Result.ok(encoding.b64url_encode(res.data));
};

/**
 * Calculates a PKCE Code Challenge from a verifier using S256.
 * 
 * @param {string} verifier - PKCE verifier string
 * @returns {string} - Base64URL encoded challenge
 */
export function calculate_challenge(native, verifier) {
	return encoding.b64url_encode(hash.hash_sha256(native, verifier));
};

/**
 * Generates a PKCE Verifier and Challenge pair.
 * 
 * @param {object} io - I/O provider
 * @param {number} [len] - Optional verifier length
 * @returns {object} - Result Object {ok, data/error}
 */
export function pair(native, len) {
	let verifier = generate_verifier(native, len);
	if (!verifier.ok)
    return verifier;

	return Result.ok({
    verifier: verifier.data, 
    challenge: calculate_challenge(native, verifier.data)
  });
};
