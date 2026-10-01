"use strict";

import { b64url_decode } from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import { INVALID_EC_PARAMS_ENCODING, INVALID_RSA_PARAMS_ENCODING, MISSING_EC_PARAMS, MISSING_KTY, MISSING_RSA_PARAMS, PEM_CONVERSION_FAILED, UNSUPPORTED_CURVE, UNSUPPORTED_KTY } from 'luci_sso.errors';

function rsa_to_pem(native, jwk) {
	if (!jwk.n || !jwk.e)
		return Result.err(MISSING_RSA_PARAMS);

	let n_res = b64url_decode(jwk.n);
	let e_res = b64url_decode(jwk.e);

	if (!n_res.ok || !e_res.ok)
		return Result.err(INVALID_RSA_PARAMS_ENCODING);

	let pem = native.jwk_rsa_to_pem(n_res.data, e_res.data);

	if (!pem)
		return Result.err(PEM_CONVERSION_FAILED);

	return Result.ok(pem);
}

function ec_to_pem(native, jwk) {
	if (jwk.crv != "P-256")
		return Result.err(UNSUPPORTED_CURVE);

	if (!jwk.x || !jwk.y)
		return Result.err(MISSING_EC_PARAMS);

	let x_res = b64url_decode(jwk.x);
	let y_res = b64url_decode(jwk.y);

	if (!x_res.ok || !y_res.ok)
		return Result.err(INVALID_EC_PARAMS_ENCODING);

	let pem = native.jwk_ec_p256_to_pem(x_res.data, y_res.data);

	if (!pem)
		return Result.err(PEM_CONVERSION_FAILED);

	return Result.ok(pem);
}

/**
 * Logic for managing and converting JSON Web Keys (JWK).
 * Pure utility module for key transformations.
 */

/**
 * The native backends' rules for an RSA key that verifies ID tokens,
 * mirrored here so the settings page's connection test judges a key as a
 * login does. The native module enforces them; these copies only explain a
 * refusal:
 *
 *   RSA_MIN_BITS  native_verify_rs256() refuses a modulus shorter than
 *                 NATIVE_RSA_MIN_BITS (mod/native.h). `make lint`
 *                 (devenv/scripts/check-native-mirrors.sh) fails when the
 *                 two differ.
 *   RSA_EXPONENT  native_api_jwk_rsa_to_pem() (mod/native_api.c) accepts
 *                 only the public exponent 65537, as exactly the three bytes
 *                 01 00 01: base64url "AQAB".
 */
export const RSA_MIN_BITS = 2048;
export const RSA_EXPONENT = "AQAB";

/**
 * The bit length of an RSA JWK's modulus `n`, leading zero bytes ignored,
 * as the backends count it.
 *
 * @param {object} jwk - An RSA JWK
 * @returns {?number} The bit length, or null when `n` is missing, empty or
 *   not base64url
 */
export function rsa_bits(jwk) {
	if (type(jwk) != "object" || type(jwk.n) != "string") return null;
	let res = b64url_decode(jwk.n);
	if (!res.ok) return null;
	let n = res.data;
	let i = 0;
	while (i < length(n) && ord(n, i) == 0) i++;
	if (i == length(n)) return null;
	let bits = (length(n) - i) * 8;
	for (let top = ord(n, i); top < 128; top *= 2) bits--;
	return bits;
};

/**
 * Whether an RSA JWK's public exponent `e` is the one the backends accept
 * (RSA_EXPONENT): 65537, as exactly three bytes. A leading zero byte, as in
 * "AAEAAQ", is refused too.
 *
 * @param {object} jwk - An RSA JWK
 * @returns {boolean}
 */
export function rsa_exponent_supported(jwk) {
	if (type(jwk) != "object" || type(jwk.e) != "string") return false;
	let res = b64url_decode(jwk.e);
	return res.ok && res.data === b64url_decode(RSA_EXPONENT).data;
};

/**
 * Converts a JWK object to a PEM string.
 * Supports RSA and EC (P-256) keys. Symmetric (`oct`) keys are refused with
 * UNSUPPORTED_KTY: ID tokens are verified with RS256 or ES256 only.
 * 
 * @param {module:luci_sso.native} native Compiled crypto extension; `native.jwk_rsa_to_pem()` or `native.jwk_ec_p256_to_pem()` performs the conversion.
 * @param {*} jwk JWK object; must have `kty` (`"RSA"` or `"EC"`) plus the corresponding key fields.
 * @returns {Result}
 */
export function to_pem(native, jwk) {
	if (!jwk || type(jwk) != "object")
		die("CONTRACT_VIOLATION: jwk_to_pem expects object jwk");

	if (!jwk.kty)
		return Result.err(MISSING_KTY);

	let conversion_table = {
		"RSA": rsa_to_pem,
		"EC": ec_to_pem
	};

	let fn = conversion_table[jwk.kty];
	if (!fn)
		return Result.err(UNSUPPORTED_KTY);

	return fn(native, jwk);
};
