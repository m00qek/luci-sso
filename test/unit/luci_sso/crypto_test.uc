import { describe, it, assert, contains, regex, has_length } from 'utest';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import { PLUMBING_RSA } from 'fixtures.rsa';
import { MOCK_JWK } from 'fixtures.oidc';

const B64URL = /^[A-Za-z0-9_-]+$/;
const HEX64  = /^[0-9a-f]{64}$/;

// ─── facade delegates to submodules ──────────────────────────────────────────

describe('crypto: facade delegation', () => {
	it('constant_time_eq is available and works', () => {
		assert.match(true,  crypto.constant_time_eq('abc', 'abc'));
		assert.match(false, crypto.constant_time_eq('abc', 'xyz'));
	});

	it('jws_sign returns a three-part token', () => {
		let res = crypto.jws_sign(native, { sub: 'u1' }, 'secret');
		assert.match(contains({ ok: true }), res);
		assert.match(3, length(split(res.data, '.')));
	});

	it('jws_verify roundtrip', () => {
		let signed = crypto.jws_sign(native, { sub: 'u2' }, 'secret');
		assert.match(contains({ ok: true }), signed);
		assert.match(contains({ ok: true, data: contains({ sub: 'u2' }) }), crypto.jws_verify(native, signed.data, 'secret'));
	});

	it('random returns the correct number of bytes', () => {
		assert.match(contains({ ok: true, data: has_length(24) }), crypto.random(native, 24));
	});

	it('hash_sha256 returns 32 raw bytes', () => {
		assert.match(contains({ ok: true, data: has_length(32) }), crypto.hash_sha256(native, 'hello'));
	});

	it('hash_sha256_hex returns 64 hex chars', () => {
		assert.match(contains({ ok: true, data: regex(HEX64) }), crypto.hash_sha256_hex(native, 'hello'));
	});

	it('pkce_pair returns verifier and challenge in base64url', () => {
		assert.match(contains({ ok: true, data: contains({ verifier: regex(B64URL), challenge: regex(B64URL) }) }), crypto.pkce_pair(native));
	});

	it('jwt_verify delegates to jwt.verify (PLUMBING_RSA reaches MISSING_EXP_CLAIM)', () => {
		assert.match(
			contains({ ok: false, error: 'MISSING_EXP_CLAIM' }),
			crypto.jwt_verify(native, PLUMBING_RSA.token, PLUMBING_RSA.pubkey, {
				alg: 'RS256',
				iss: 'https://issuer.example.com',
				aud: 'test-client',
				now: 1700000000,
				clock_tolerance: 0,
			})
		);
	});

	it('jwk_to_pem delegates to jwk.to_pem', () => {
		assert.match(contains({ ok: true, data: regex(/^-----BEGIN/) }), crypto.jwk_to_pem(native, MOCK_JWK));
	});

	it('safe_id returns [INVALID] for short tokens', () => {
		assert.match('[INVALID]', crypto.safe_id(native, 'short'));
	});

	it('safe_id returns a 16-char hex string for valid tokens', () => {
		assert.match(regex(/^[0-9a-f]{16}$/), crypto.safe_id(native, 'long-enough-token-here'));
	});
});
