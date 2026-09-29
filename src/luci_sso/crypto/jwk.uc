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
