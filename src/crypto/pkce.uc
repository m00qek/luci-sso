import * as Result from 'luci_sso.result';
import * as encoding from 'luci_sso.encoding';

import * as base from 'luci_sso.crypto.base';
import * as hash from 'luci_sso.crypto.hash';


/**
 * Generates a PKCE Code Verifier.
 * 
 * @param {object} native - Native crypto provider
 * @param {number} [len=43] - Length of verifier
 * @returns {object} - Result Object {ok, data/error}
 */
export function generate_verifier(native, len) {
	let byte_len = len || 43;
	if (byte_len < 32 || byte_len > 96)
		die("CONTRACT_VIOLATION: PKCE verifier must be 32-96 bytes");

	let result = base.random(native, byte_len);
	if (!result.ok)
		return result;

	return encoding.b64url_encode(result.data);
};

/**
 * Calculates a PKCE Code Challenge from a verifier using S256.
 * 
 * @param {object} native - Native crypto provider
 * @param {string} verifier - PKCE verifier string
 * @returns {object} - Result Object {ok, data/error}
 */
export function calculate_challenge(native, verifier) {
	let res = hash.sha256(native, verifier);
	if (!res.ok)
    return res;

	return encoding.b64url_encode(res.data);
};

/**
 * Generates a PKCE Verifier and Challenge pair.
 * 
 * @param {object} native - Native crypto provider
 * @param {number} [len] - Optional verifier length
 * @returns {object} - Result Object {ok, data/error}
 */
export function pair(native, len) {
	let verifier = generate_verifier(native, len);
	if (!verifier.ok)
		return verifier;

	let challenge = calculate_challenge(native, verifier.data);
	if (!challenge.ok)
		return challenge;

	return Result.ok({
		verifier: verifier.data, 
		challenge: challenge.data
	});
};
