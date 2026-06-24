import { describe, it, afterEach, assert, contains, regex, has_length, pred } from 'utest';
import * as crypto from 'luci_sso.crypto';
import * as real_native from 'luci_sso.native';
import { PLUMBING_RSA } from 'tier1.fixtures';
import { MOCK_JWK } from 'tier2.fixtures';

const B64URL = /^[A-Za-z0-9_-]+$/;
const HEX64  = /^[0-9a-f]{64}$/;

// Returns a native stub that routes calls to the real native and counts invocations
function make_interceptor() {
	let calls = { sha256: 0, hmac_sha256: 0, random: 0 };
	return {
		intercepting: {
			sha256: (s) => { calls.sha256++; return real_native.sha256(s); },
			hmac_sha256: (k, m) => { calls.hmac_sha256++; return real_native.hmac_sha256(k, m); },
			random: (n) => { calls.random++; return real_native.random(n); },
			verify_rs256: real_native.verify_rs256,
			verify_es256: real_native.verify_es256,
			jwk_rsa_to_pem: real_native.jwk_rsa_to_pem,
			jwk_ec_p256_to_pem: real_native.jwk_ec_p256_to_pem,
		},
		calls,
	};
}

// ─── set_native ──────────────────────────────────────────────────────────────

describe('crypto: set_native', () => {
	afterEach(() => { crypto.set_native(null); });

	it('null restores the real provider so hash_sha256 succeeds', () => {
		crypto.set_native({ sha256: () => null });
		assert.match(contains({ ok: false }), crypto.hash_sha256('test'));

		crypto.set_native(null);
		assert.match(contains({ ok: true }), crypto.hash_sha256('test'));
	});

	it('intercepts calls through the facade', () => {
		let spy = make_interceptor();
		crypto.set_native(spy.intercepting);
		crypto.hash_sha256('hello');
		assert.match(pred((n) => n >= 1), spy.calls.sha256);
	});

	it('intercepted random call is tracked', () => {
		let spy = make_interceptor();
		crypto.set_native(spy.intercepting);
		crypto.random(16);
		assert.match(pred((n) => n >= 1), spy.calls.random);
	});

	it('set_native(null) after override restores correct behaviour', () => {
		crypto.set_native({ sha256: () => null });
		crypto.set_native(null);
		assert.match(contains({ ok: true, data: has_length(32) }), crypto.hash_sha256('sanity'));
	});
});

// ─── facade delegates to submodules ──────────────────────────────────────────

describe('crypto: facade delegation', () => {
	it('constant_time_eq is available and works', () => {
		assert.match(true,  crypto.constant_time_eq('abc', 'abc'));
		assert.match(false, crypto.constant_time_eq('abc', 'xyz'));
	});

	it('jws_sign returns a three-part token', () => {
		let res = crypto.jws_sign({ sub: 'u1' }, 'secret');
		assert.match(contains({ ok: true }), res);
		assert.match(3, length(split(res.data, '.')));
	});

	it('jws_verify roundtrip', () => {
		let signed = crypto.jws_sign({ sub: 'u2' }, 'secret');
		assert.match(contains({ ok: true }), signed);
		assert.match(contains({ ok: true, data: contains({ sub: 'u2' }) }), crypto.jws_verify(signed.data, 'secret'));
	});

	it('random returns the correct number of bytes', () => {
		assert.match(contains({ ok: true, data: has_length(24) }), crypto.random(24));
	});

	it('hash_sha256 returns 32 raw bytes', () => {
		assert.match(contains({ ok: true, data: has_length(32) }), crypto.hash_sha256('hello'));
	});

	it('hash_sha256_hex returns 64 hex chars', () => {
		assert.match(contains({ ok: true, data: regex(HEX64) }), crypto.hash_sha256_hex('hello'));
	});

	it('pkce_pair returns verifier and challenge in base64url', () => {
		assert.match(contains({ ok: true, data: contains({ verifier: regex(B64URL), challenge: regex(B64URL) }) }), crypto.pkce_pair());
	});

	it('jwt_verify delegates to jwt.verify (PLUMBING_RSA reaches MISSING_EXP_CLAIM)', () => {
		assert.match(
			contains({ ok: false, error: 'MISSING_EXP_CLAIM' }),
			crypto.jwt_verify(PLUMBING_RSA.token, PLUMBING_RSA.pubkey, {
				alg: 'RS256',
				iss: 'https://issuer.example.com',
				aud: 'test-client',
				now: 1700000000,
				clock_tolerance: 0,
			})
		);
	});

	it('jwk_to_pem delegates to jwk.to_pem', () => {
		assert.match(contains({ ok: true, data: regex(/^-----BEGIN/) }), crypto.jwk_to_pem(MOCK_JWK));
	});

	it('safe_id returns [INVALID] for short tokens', () => {
		assert.match('[INVALID]', crypto.safe_id('short'));
	});

	it('safe_id returns a 16-char hex string for valid tokens', () => {
		assert.match(regex(/^[0-9a-f]{16}$/), crypto.safe_id('long-enough-token-here'));
	});
});
