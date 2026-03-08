import * as _native from 'luci_sso.native';

import * as Result from 'luci_sso.result';

import * as c_jws from 'luci_sso.crypto.jws';
import * as c_jwt from 'luci_sso.crypto.jwt';
import * as c_jwk from 'luci_sso.crypto.jwk';
import * as c_base from 'luci_sso.crypto.base';
import * as c_hash from 'luci_sso.crypto.hash';
import * as c_pkce from 'luci_sso.crypto.pkce';

const MAX_TOKEN_SIZE = 16384; // 16 KB

let native = _native;

/**
 * Overrides the native provider (used for testing CSPRNG failures).
 * @param {object} n - Mock native provider
 */
export function set_native(n) {
	native = n || _native;
};

// --- JSON Helpers ---
export function constant_time_eq(a, b) {
	return c_base.constant_time_eq(a, b);
};

// --- Public API ---

export function jws_sign(payload, secret) {
	return c_jws.sign(native, payload, secret);
};

export function jws_verify(token, secret) {
	return c_jws.verify(native, token, secret);
};

export function jwt_verify(token, pubkey, options) {
	return c_jwt.verify(native, token, pubkey, options);
};

export function random(len) {
	return c_base.random(native, len);
};

export function hash_sha256(str) {
	return c_hash.sha256(native, str);
};

export function hash_sha256_hex(str) {
	return c_hash.sha256_hex(native, str);
};

export function pkce_pair(len) {
	return c_pkce.pair(native, len);
};

export function jwk_to_pem(jwk) {
	return c_jwk.to_pem(native, jwk);
};

export function safe_id(token) {
	return c_base.safe_id(native, token);
};
