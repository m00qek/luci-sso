import { describe, it, assert, equals, contains, not, regex, is_type, has_length } from 'utest';
import * as real_native from 'luci_sso.native';
import * as jwk from 'luci_sso.crypto.jwk';
import * as encoding from 'luci_sso.encoding';
import { MOCK_JWK } from 'tier2.fixtures';
import { PLUMBING_RSA } from 'tier1.fixtures';
import * as f0 from 'tier0.fixtures';
import { RSA_JWK_N, JWK_EC_X_B64, JWK_EC_Y_B64, hex_to_bin } from 'fixtures.native';

// EC P-256 test key — RFC 7517 Appendix C
// x and y are each 43 base64url chars = 32 bytes (the P-256 field size)
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

// ─── contract ────────────────────────────────────────────────────────────────

describe('crypto.jwk: to_pem — contract', () => {
	it('dies for null', () => {
		assert.throws(() => jwk.to_pem(real_native, null));
	});

	it('dies for non-object types', () => {
		for (let v in ['string', 42, []]) {
			assert.throws(() => jwk.to_pem(real_native, v));
		}
	});

	it('returns MISSING_KTY when kty field is absent', () => {
		assert.match(contains({ ok: false, error: 'MISSING_KTY' }), jwk.to_pem(real_native, { n: 'x', e: 'y' }));
	});

	it('returns UNSUPPORTED_KTY for unknown key types', () => {
		for (let kty in ['DH', 'OKP', 'UNKNOWN']) {
			assert.match(contains({ ok: false, error: 'UNSUPPORTED_KTY' }), jwk.to_pem(real_native, { kty }));
		}
	});
});

// ─── RSA ─────────────────────────────────────────────────────────────────────

describe('crypto.jwk: to_pem — RSA', () => {
	it('returns PEM for a valid RSA JWK', () => {
		assert.match(contains({ ok: true, data: regex(PEM_HEADER) }), jwk.to_pem(real_native, MOCK_JWK));
	});

	it('returns MISSING_RSA_PARAMS when n is absent', () => {
		assert.match(contains({ ok: false, error: 'MISSING_RSA_PARAMS' }), jwk.to_pem(real_native, { kty: 'RSA', e: MOCK_JWK.e }));
	});

	it('returns MISSING_RSA_PARAMS when e is absent', () => {
		assert.match(contains({ ok: false, error: 'MISSING_RSA_PARAMS' }), jwk.to_pem(real_native, { kty: 'RSA', n: MOCK_JWK.n }));
	});

	it('returns INVALID_RSA_PARAMS_ENCODING for non-base64url n', () => {
		assert.match(contains({ ok: false, error: 'INVALID_RSA_PARAMS_ENCODING' }), jwk.to_pem(real_native, { kty: 'RSA', n: '!!!', e: MOCK_JWK.e }));
	});

	it('returns INVALID_RSA_PARAMS_ENCODING for non-base64url exponent e', () => {
		assert.match(contains({ ok: false, error: 'INVALID_RSA_PARAMS_ENCODING' }), jwk.to_pem(real_native, { kty: 'RSA', n: MOCK_JWK.n, e: '!!!' }));
	});

	it('returns PEM_CONVERSION_FAILED for non-F4 exponent', () => {
		// e=AQAB is 65537; AQID is 65539 — not the standard F4 exponent
		assert.match(contains({ ok: false, error: 'PEM_CONVERSION_FAILED' }), jwk.to_pem(real_native, { kty: 'RSA', n: MOCK_JWK.n, e: 'AQID' }));
	});

	it('produced PEM validates a real PLUMBING_RSA JWT signature', () => {
		let res = jwk.to_pem(real_native, { kty: 'RSA', n: RSA_JWK_N, e: 'AQAB' });
		assert.match(contains({ ok: true }), res);
		let parts = split(PLUMBING_RSA.token, '.');
		let sig = encoding.b64url_decode(parts[2]);
		assert.match(contains({ ok: true }), sig);
		assert.match(true, real_native.verify_rs256(`${parts[0]}.${parts[1]}`, sig.data, res.data));
	});
});

// ─── EC ──────────────────────────────────────────────────────────────────────

describe('crypto.jwk: to_pem — EC', () => {
	it('returns PEM for a valid P-256 JWK', () => {
		assert.match(contains({ ok: true, data: regex(PEM_HEADER) }), jwk.to_pem(real_native, EC_JWK));
	});

	it('returns UNSUPPORTED_CURVE for non-P-256 curves', () => {
		for (let crv in ['P-384', 'P-521', 'Ed25519']) {
			assert.match(contains({ ok: false, error: 'UNSUPPORTED_CURVE' }), jwk.to_pem(real_native, { kty: 'EC', crv, x: EC_JWK.x, y: EC_JWK.y }));
		}
	});

	it('returns MISSING_EC_PARAMS when x is absent', () => {
		assert.match(contains({ ok: false, error: 'MISSING_EC_PARAMS' }), jwk.to_pem(real_native, { kty: 'EC', crv: 'P-256', y: EC_JWK.y }));
	});

	it('returns MISSING_EC_PARAMS when y is absent', () => {
		assert.match(contains({ ok: false, error: 'MISSING_EC_PARAMS' }), jwk.to_pem(real_native, { kty: 'EC', crv: 'P-256', x: EC_JWK.x }));
	});

	it('returns INVALID_EC_PARAMS_ENCODING for non-base64url coordinates', () => {
		assert.match(contains({ ok: false, error: 'INVALID_EC_PARAMS_ENCODING' }), jwk.to_pem(real_native, { kty: 'EC', crv: 'P-256', x: '!!!', y: EC_JWK.y }));
	});

	it('produced PEM validates a known EC_256 signature', () => {
		let res = jwk.to_pem(real_native, { kty: 'EC', crv: 'P-256', x: JWK_EC_X_B64, y: JWK_EC_Y_B64 });
		assert.match(contains({ ok: true }), res);
		assert.match(true, real_native.verify_es256(f0.EC_256.msg, hex_to_bin(f0.EC_256.sig_hex), res.data));
	});

	it('returns PEM_CONVERSION_FAILED when coordinates are not 32 bytes', () => {
		// 10 bytes of zeros in base64url = "AAAAAAAAAAAAAA" (14 chars, not 43)
		let short = 'AAAAAAAAAAAAAA';
		assert.match(contains({ ok: false, error: 'PEM_CONVERSION_FAILED' }), jwk.to_pem(real_native, { kty: 'EC', crv: 'P-256', x: short, y: short }));
	});
});

// ─── oct ─────────────────────────────────────────────────────────────────────

describe('crypto.jwk: to_pem — oct', () => {
	it('returns the raw decoded key bytes for a valid oct JWK', () => {
		let res = jwk.to_pem(real_native, OCT_JWK);
		// oct keys are returned as raw bytes, not PEM
		assert.match(contains({ ok: true, data: is_type('string') }), res);
		assert.match(not(equals('')), res.data);
	});

	it('RFC 7516 Appendix C example key decodes to exactly 64 bytes (512-bit key)', () => {
		assert.match(contains({ ok: true, data: has_length(64) }), jwk.to_pem(real_native, OCT_JWK));
	});

	it('returns MISSING_OCT_PARAM when k is absent', () => {
		assert.match(contains({ ok: false, error: 'MISSING_OCT_PARAM' }), jwk.to_pem(real_native, { kty: 'oct' }));
	});

	it('returns INVALID_OCT_PARAM_ENCODING for non-base64url k', () => {
		assert.match(contains({ ok: false, error: 'INVALID_OCT_PARAM_ENCODING' }), jwk.to_pem(real_native, { kty: 'oct', k: '!!!' }));
	});
});
