import { describe, it, prop, gen, assert, equals, not, contains, regex, is_type } from 'utest';
import * as real_native from 'luci_sso.native';
import * as pkce from 'luci_sso.crypto.pkce';

const broken = { random: () => null, sha256: () => null };

// RFC 7636 §4.1: code_verifier is [A-Z a-z 0-9 - . _ ~] which in base64url is [A-Za-z0-9_-]
const B64URL = /^[A-Za-z0-9_-]+$/;

// ─── generate_verifier ───────────────────────────────────────────────────────

describe('crypto.pkce: generate_verifier', () => {
	it('default produces a base64url string', () => {
		assert.match(contains({ ok: true, data: regex(B64URL) }), pkce.generate_verifier(real_native));
	});

	it('dies when byte_len is below 32', () => {
		assert.throws(() => pkce.generate_verifier(real_native, 31));
	});

	it('dies when byte_len is above 96', () => {
		assert.throws(() => pkce.generate_verifier(real_native, 97));
	});

	it('accepts the minimum boundary (32)', () => {
		assert.match(contains({ ok: true, data: regex(B64URL) }), pkce.generate_verifier(real_native, 32));
	});

	it('accepts the maximum boundary (96)', () => {
		assert.match(contains({ ok: true, data: regex(B64URL) }), pkce.generate_verifier(real_native, 96));
	});

	it('returns CSPRNG_FAILURE when native.random fails', () => {
		assert.match(contains({ ok: false, error: 'CSPRNG_FAILURE' }), pkce.generate_verifier(broken));
	});

	it('produces distinct verifiers on successive calls', () => {
		let a = pkce.generate_verifier(real_native);
		let b = pkce.generate_verifier(real_native);
		assert.match(contains({ ok: true }), a);
		assert.match(contains({ ok: true }), b);
		assert.match(not(equals(a.data)), b.data);
	});

	prop('any valid byte_len produces base64url output',
		gen.int(32, 96),
		(n, ctx) => {
			ctx.classify('min boundary (32)', n === 32);
			ctx.classify('max boundary (96)', n === 96);
			assert.match(contains({ ok: true, data: regex(B64URL) }), pkce.generate_verifier(real_native, n));
		}
	);
});

// ─── calculate_challenge ─────────────────────────────────────────────────────

describe('crypto.pkce: calculate_challenge', () => {
	it('returns a base64url string', () => {
		assert.match(contains({ ok: true, data: regex(B64URL) }), pkce.calculate_challenge(real_native, 'any-verifier-string'));
	});

	it('is deterministic for the same verifier', () => {
		let v = 'fixed-verifier-value';
		let a = pkce.calculate_challenge(real_native, v);
		let b = pkce.calculate_challenge(real_native, v);
		assert.match(contains({ ok: true }), a);
		assert.match(contains({ ok: true }), b);
		assert.match(a.data, b.data);
	});

	it('RFC 7636 §B.1 known vector', () => {
		// verifier and expected challenge from the RFC test appendix
		assert.match(
			contains({ ok: true, data: equals('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM') }),
			pkce.calculate_challenge(real_native, 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
		);
	});

	it('different verifiers produce different challenges', () => {
		let a = pkce.calculate_challenge(real_native, 'verifier-one');
		let b = pkce.calculate_challenge(real_native, 'verifier-two');
		assert.match(contains({ ok: true }), a);
		assert.match(contains({ ok: true }), b);
		assert.match(not(equals(a.data)), b.data);
	});

	it('fails when native.sha256 returns null', () => {
		assert.match(contains({ ok: false }), pkce.calculate_challenge(broken, 'verifier'));
	});

	prop('any verifier string produces a base64url challenge',
		gen.string({ min_len: 1, max_len: 200 }),
		(v, ctx) => {
			ctx.classify('short (≤10)', length(v) <= 10);
			assert.match(contains({ ok: true, data: regex(B64URL) }), pkce.calculate_challenge(real_native, v));
		}
	);
});

// ─── pair ────────────────────────────────────────────────────────────────────

describe('crypto.pkce: pair', () => {
	it('returns ok with string verifier and challenge fields', () => {
		assert.match(contains({ ok: true, data: contains({ verifier: is_type('string'), challenge: is_type('string') }) }), pkce.pair(real_native));
	});

	it('verifier and challenge are both valid base64url', () => {
		assert.match(contains({ ok: true, data: contains({ verifier: regex(B64URL), challenge: regex(B64URL) }) }), pkce.pair(real_native));
	});

	it('challenge equals base64url(sha256(verifier)) — S256 method', () => {
		let res = pkce.pair(real_native);
		assert.match(contains({ ok: true }), res);
		let expected = pkce.calculate_challenge(real_native, res.data.verifier);
		assert.match(contains({ ok: true }), expected);
		assert.match(expected.data, res.data.challenge);
	});

	it('pair() propagates CSPRNG failure', () => {
		assert.match(contains({ ok: false }), pkce.pair(broken));
	});

	it('successive pairs are distinct', () => {
		let a = pkce.pair(real_native);
		let b = pkce.pair(real_native);
		assert.match(contains({ ok: true }), a);
		assert.match(contains({ ok: true }), b);
		assert.match(not(equals(a.data.verifier)), b.data.verifier);
	});

	prop('pair is always internally consistent (S256 invariant)',
		gen.int(32, 96),
		(n) => {
			let res = pkce.pair(real_native, n);
			assert.match(contains({ ok: true }), res);
			let expected = pkce.calculate_challenge(real_native, res.data.verifier);
			assert.match(contains({ ok: true }), expected);
			assert.match(expected.data, res.data.challenge);
		}
	);
});
