import { describe, it, assert, equals, not, contains, regex, is_type, has_length, mock, spy } from 'utest';
import * as jwk from 'luci_sso.crypto.jwk';
import * as encoding from 'luci_sso.encoding';

// jwk.to_pem fakes `native` (data-first) so these tests exercise only the
// wrapper: contract guards, the kty dispatch, param presence/encoding checks,
// forwarding decoded key material to native.jwk_*_to_pem, and the null →
// PEM_CONVERSION_FAILED branch. Real key-conversion / signature validation
// lives in test/native.

const FAKE_PEM = '-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n';

// Minimal RSA JWK with valid base64url params (n = b64url("1234567890"), e = 65537).
const RSA_JWK = { kty: 'RSA', n: 'MTIzNDU2Nzg5MA', e: 'AQAB' };

// EC P-256 test key — RFC 7517 Appendix C. x and y are each 43 base64url chars.
const EC_JWK = {
	kty: 'EC',
	crv: 'P-256',
	x:   'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
	y:   '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
};

// Symmetric octet key — RFC 7516 Appendix C
const OCT_JWK = {
	kty: 'oct',
	k:   'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow',
};

const PEM_HEADER = /^-----BEGIN/;

// native returns a canned PEM for whichever conversion is invoked (data-first).
function with_pem(fn) {
	mock.inject('native', { strict: true, data: { jwk_rsa_to_pem: FAKE_PEM, jwk_ec_p256_to_pem: FAKE_PEM } }, fn);
}

// native returns null for whichever conversion is invoked → PEM_CONVERSION_FAILED.
function with_null(fn) {
	mock.inject('native', { strict: true, data: { jwk_rsa_to_pem: null, jwk_ec_p256_to_pem: null } }, fn);
}

// native must never be called — any call dies (strict, no data).
function with_strict(fn) {
	mock.inject('native', { strict: true }, fn);
}

// ─── contract ────────────────────────────────────────────────────────────────

describe('crypto.jwk: to_pem — contract', () => {
	it('dies for null', () => with_strict((native) => {
		assert.throws(() => jwk.to_pem(native, null));
	}));

	it('dies for non-object types', () => with_strict((native) => {
		for (let v in ['string', 42, []]) {
			assert.throws(() => jwk.to_pem(native, v));
		}
	}));

	it('returns MISSING_KTY when kty field is absent', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'MISSING_KTY' }), jwk.to_pem(native, { n: 'x', e: 'y' }));
	}));

	it('returns UNSUPPORTED_KTY for unknown key types', () => with_strict((native) => {
		for (let kty in ['DH', 'OKP', 'UNKNOWN']) {
			assert.match(contains({ ok: false, error: 'UNSUPPORTED_KTY' }), jwk.to_pem(native, { kty }));
		}
	}));
});

// ─── RSA ─────────────────────────────────────────────────────────────────────

describe('crypto.jwk: to_pem — RSA', () => {
	it('returns the native PEM for a valid RSA JWK', () => with_pem((native) => {
		assert.match(contains({ ok: true, data: regex(PEM_HEADER) }), jwk.to_pem(native, RSA_JWK));
	}));

	it('forwards the decoded n and e bytes to native.jwk_rsa_to_pem', () => with_pem((native) => {
		jwk.to_pem(native, RSA_JWK);
		let call = spy(native).calls.jwk_rsa_to_pem[0];
		assert.match(encoding.b64url_decode(RSA_JWK.n).data, call[0]);
		assert.match(encoding.b64url_decode(RSA_JWK.e).data, call[1]);
	}));

	it('returns MISSING_RSA_PARAMS when n is absent', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'MISSING_RSA_PARAMS' }), jwk.to_pem(native, { kty: 'RSA', e: RSA_JWK.e }));
	}));

	it('returns MISSING_RSA_PARAMS when e is absent', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'MISSING_RSA_PARAMS' }), jwk.to_pem(native, { kty: 'RSA', n: RSA_JWK.n }));
	}));

	it('returns INVALID_RSA_PARAMS_ENCODING for non-base64url n', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'INVALID_RSA_PARAMS_ENCODING' }), jwk.to_pem(native, { kty: 'RSA', n: '!!!', e: RSA_JWK.e }));
	}));

	it('returns INVALID_RSA_PARAMS_ENCODING for non-base64url exponent e', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'INVALID_RSA_PARAMS_ENCODING' }), jwk.to_pem(native, { kty: 'RSA', n: RSA_JWK.n, e: '!!!' }));
	}));

	it('returns PEM_CONVERSION_FAILED when native.jwk_rsa_to_pem returns null', () => with_null((native) => {
		assert.match(contains({ ok: false, error: 'PEM_CONVERSION_FAILED' }), jwk.to_pem(native, RSA_JWK));
	}));
});

// ─── EC ──────────────────────────────────────────────────────────────────────

describe('crypto.jwk: to_pem — EC', () => {
	it('returns the native PEM for a valid P-256 JWK', () => with_pem((native) => {
		assert.match(contains({ ok: true, data: regex(PEM_HEADER) }), jwk.to_pem(native, EC_JWK));
	}));

	it('forwards the decoded x and y bytes to native.jwk_ec_p256_to_pem', () => with_pem((native) => {
		jwk.to_pem(native, EC_JWK);
		let call = spy(native).calls.jwk_ec_p256_to_pem[0];
		assert.match(encoding.b64url_decode(EC_JWK.x).data, call[0]);
		assert.match(encoding.b64url_decode(EC_JWK.y).data, call[1]);
	}));

	it('returns UNSUPPORTED_CURVE for non-P-256 curves', () => with_strict((native) => {
		for (let crv in ['P-384', 'P-521', 'Ed25519']) {
			assert.match(contains({ ok: false, error: 'UNSUPPORTED_CURVE' }), jwk.to_pem(native, { kty: 'EC', crv, x: EC_JWK.x, y: EC_JWK.y }));
		}
	}));

	it('returns MISSING_EC_PARAMS when x is absent', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'MISSING_EC_PARAMS' }), jwk.to_pem(native, { kty: 'EC', crv: 'P-256', y: EC_JWK.y }));
	}));

	it('returns MISSING_EC_PARAMS when y is absent', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'MISSING_EC_PARAMS' }), jwk.to_pem(native, { kty: 'EC', crv: 'P-256', x: EC_JWK.x }));
	}));

	it('returns INVALID_EC_PARAMS_ENCODING for non-base64url coordinates', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'INVALID_EC_PARAMS_ENCODING' }), jwk.to_pem(native, { kty: 'EC', crv: 'P-256', x: '!!!', y: EC_JWK.y }));
	}));

	it('returns PEM_CONVERSION_FAILED when native.jwk_ec_p256_to_pem returns null', () => with_null((native) => {
		assert.match(contains({ ok: false, error: 'PEM_CONVERSION_FAILED' }), jwk.to_pem(native, EC_JWK));
	}));
});

// ─── oct ─────────────────────────────────────────────────────────────────────
// oct keys are decoded directly by the wrapper — native is never called.

describe('crypto.jwk: to_pem — oct', () => {
	it('returns the raw decoded key bytes for a valid oct JWK', () => with_strict((native) => {
		let res = jwk.to_pem(native, OCT_JWK);
		// oct keys are returned as raw bytes, not PEM
		assert.match(contains({ ok: true, data: is_type('string') }), res);
		assert.match(not(equals('')), res.data);
	}));

	it('RFC 7516 Appendix C example key decodes to exactly 64 bytes (512-bit key)', () => with_strict((native) => {
		assert.match(contains({ ok: true, data: has_length(64) }), jwk.to_pem(native, OCT_JWK));
	}));

	it('returns MISSING_OCT_PARAM when k is absent', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'MISSING_OCT_PARAM' }), jwk.to_pem(native, { kty: 'oct' }));
	}));

	it('returns INVALID_OCT_PARAM_ENCODING for non-base64url k', () => with_strict((native) => {
		assert.match(contains({ ok: false, error: 'INVALID_OCT_PARAM_ENCODING' }), jwk.to_pem(native, { kty: 'oct', k: '!!!' }));
	}));
});
