import { b64url_decode } from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';

function rsa_to_pem(native, jwk) {
	if (!jwk.n || !jwk.e)
		return Result.err("MISSING_RSA_PARAMS");

	let n_res = b64url_decode(jwk.n);
	let e_res = b64url_decode(jwk.e);

	if (!n_res.ok || !e_res.ok)
		return Result.err("INVALID_RSA_PARAMS_ENCODING");

	let pem = native.jwk_rsa_to_pem(n_res.data, e_res.data);

	if (!pem)
		return Result.err("PEM_CONVERSION_FAILED");

	return Result.ok(pem);
};

function ec_to_pem(native, jwk) {
	if (jwk.crv != "P-256")
		return Result.err("UNSUPPORTED_CURVE");

	if (!jwk.x || !jwk.y)
		return Result.err("MISSING_EC_PARAMS");

	let x_res = b64url_decode(jwk.x);
	let y_res = b64url_decode(jwk.y);

	if (!x_res.ok || !y_res.ok)
		return Result.err("INVALID_EC_PARAMS_ENCODING");

	let pem = native.jwk_ec_p256_to_pem(x_res.data, y_res.data);

	if (!pem)
		return Result.err("PEM_CONVERSION_FAILED");

	return Result.ok(pem);
};

function oct_to_pem(native, jwk) {
	if (!jwk.k)
		return Result.err("MISSING_OCT_PARAM");

	let result = b64url_decode(jwk.k);
	if (!result.ok)
		return Result.err("INVALID_OCT_PARAM_ENCODING");

	return result;
};

/**
 * Logic for managing and converting JSON Web Keys (JWK).
 * Pure utility module for key transformations.
 */

/**
 * Converts a JWK object to a PEM string.
 * Supports RSA, EC (P-256), and octet (symmetric) key types.
 * 
 * @param {object} native - Native crypto provider
 * @param {object} jwk - JWK object
 * @returns {object} - Result Object {ok, data/error}
 */
export function to_pem(native, jwk) {
	if (!jwk || type(jwk) != "object")
		die("CONTRACT_VIOLATION: jwk_to_pem expects object jwk");

	if (!jwk.kty)
		return Result.err("MISSING_KTY");

	let conversion_table = {
		"RSA": rsa_to_pem,
		"EC": ec_to_pem,
		"oct": oct_to_pem
	};

	let fn = conversion_table[jwk.kty];
	if (!fn)
		return Result.err("UNSUPPORTED_KTY");

	return fn(native, jwk);
};
