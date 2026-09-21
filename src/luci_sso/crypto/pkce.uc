import * as Result from 'luci_sso.result';
import * as encoding from 'luci_sso.encoding';

import * as base from 'luci_sso.crypto.base';
import * as hash from 'luci_sso.crypto.hash';


/**
 * Generates a PKCE Code Verifier.
 * 
 * @param {module:luci_sso.native} native Compiled crypto extension; `native.random()` seeds the verifier.
 * @param {int} [len=43] Byte length of the verifier before base64url encoding (32–96).
 * @returns {Result}
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
 * @param {module:luci_sso.native} native Compiled crypto extension; `native.sha256()` hashes the verifier.
 * @param {string} verifier PKCE code verifier string.
 * @returns {Result}
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
 * @param {module:luci_sso.native} native Compiled crypto extension; used for both CSPRNG and SHA-256.
 * @param {int} [len] Verifier byte length (defaults to 43; range 32–96).
 * @returns {Result}
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
