import { describe, it, prop, gen, assert, equals, not, contains, regex, is_type, mock, spy } from 'utest';
import * as pkce from 'luci_sso.crypto.pkce';
import * as encoding from 'luci_sso.encoding';

// PKCE fakes `native` (data-first) to test wrapper logic: length forwarding,
// base64url encoding, the verifier→challenge wiring, and error propagation.
// The real S256 relationship (challenge == b64url(SHA-256(verifier))) is a
// native-crypto property covered in test/native.

const B64URL = /^[A-Za-z0-9_-]+$/;

// Deterministic byte string of length n.
function rnd(n) {
	let s = '';
	for (let i = 0; i < n; i++) s += chr(i % 256);
	return s;
}

const DIGEST = rnd(32);
const CHALLENGE_OF_DIGEST = encoding.b64url_encode(DIGEST).data;

// ─── generate_verifier ───────────────────────────────────────────────────────

describe('crypto.pkce: generate_verifier', () => {
	it('base64url-encodes the random bytes and forwards the default length (43)', () => {
		mock.inject('native', { strict: true, data: { random: rnd(43) } }, (native) => {
			let res = pkce.generate_verifier(native);
			assert.match(contains({ ok: true, data: encoding.b64url_encode(rnd(43)).data }), res);
			assert.match(43, spy(native).calls.random[0][0]);
		});
	});

	it('forwards an explicit byte length to native.random', () => {
		mock.inject('native', { strict: true, data: { random: rnd(64) } }, (native) => {
			assert.match(contains({ ok: true, data: regex(B64URL) }), pkce.generate_verifier(native, 64));
			assert.match(64, spy(native).calls.random[0][0]);
		});
	});

	it('accepts the 32 and 96 byte boundaries', () => {
		mock.inject('native', { strict: true, data: { random: rnd(32) } }, (native) => {
			assert.match(contains({ ok: true, data: regex(B64URL) }), pkce.generate_verifier(native, 32));
		});
		mock.inject('native', { strict: true, data: { random: rnd(96) } }, (native) => {
			assert.match(contains({ ok: true, data: regex(B64URL) }), pkce.generate_verifier(native, 96));
		});
	});

	it('dies when byte_len is below 32 or above 96 without calling native', () => {
		mock.inject('native', { strict: true }, (native) => {
			assert.throws(() => pkce.generate_verifier(native, 31));
			assert.throws(() => pkce.generate_verifier(native, 97));
		});
	});

	it('returns CSPRNG_FAILURE when native.random fails', () => {
		mock.inject('native', { strict: true, data: { random: null } }, (native) => {
			assert.match(contains({ ok: false, error: 'CSPRNG_FAILURE' }), pkce.generate_verifier(native));
		});
	});

	prop('any valid byte_len produces base64url output',
		gen.int(32, 96),
		(n, ctx) => {
			ctx.classify('min boundary (32)', n === 32);
			ctx.classify('max boundary (96)', n === 96);
			mock.inject('native', { strict: true, data: { random: rnd(n) } }, (native) => {
				assert.match(contains({ ok: true, data: regex(B64URL) }), pkce.generate_verifier(native, n));
			});
		}
	);
});

// ─── calculate_challenge ─────────────────────────────────────────────────────

describe('crypto.pkce: calculate_challenge', () => {
	it('base64url-encodes the digest and hashes the given verifier', () => {
		mock.inject('native', { strict: true, data: { sha256: DIGEST } }, (native) => {
			let res = pkce.calculate_challenge(native, 'any-verifier-string');
			assert.match(contains({ ok: true, data: CHALLENGE_OF_DIGEST }), res);
			assert.match('any-verifier-string', spy(native).calls.sha256[0][0]);
		});
	});

	it('fails when native.sha256 returns null', () => {
		mock.inject('native', { strict: true, data: { sha256: null } }, (native) => {
			assert.match(contains({ ok: false }), pkce.calculate_challenge(native, 'verifier'));
		});
	});

	prop('any verifier string produces a base64url challenge',
		gen.string({ min_len: 1, max_len: 200 }),
		(v, ctx) => {
			ctx.classify('short (≤10)', length(v) <= 10);
			mock.inject('native', { strict: true, data: { sha256: DIGEST } }, (native) => {
				assert.match(contains({ ok: true, data: regex(B64URL) }), pkce.calculate_challenge(native, v));
			});
		}
	);
});

// ─── pair ────────────────────────────────────────────────────────────────────

describe('crypto.pkce: pair', () => {
	it('returns base64url verifier and challenge fields', () => {
		mock.inject('native', { strict: true, data: { random: rnd(43), sha256: DIGEST } }, (native) => {
			let res = pkce.pair(native);
			assert.match(contains({ ok: true, data: contains({
				verifier:  encoding.b64url_encode(rnd(43)).data,
				challenge: CHALLENGE_OF_DIGEST,
			}) }), res);
			assert.match(contains({ verifier: is_type('string'), challenge: is_type('string') }), res.data);
		});
	});

	it('derives the challenge from the generated verifier (feeds it to sha256)', () => {
		mock.inject('native', { strict: true, data: { random: rnd(43), sha256: DIGEST } }, (native) => {
			let res = pkce.pair(native);
			assert.match(contains({ ok: true }), res);
			assert.match(res.data.verifier, spy(native).calls.sha256[0][0]);
		});
	});

	it('propagates a CSPRNG failure from the verifier step', () => {
		mock.inject('native', { strict: true, data: { random: null } }, (native) => {
			assert.match(contains({ ok: false, error: 'CSPRNG_FAILURE' }), pkce.pair(native));
		});
	});

	it('propagates a failure from the challenge step', () => {
		mock.inject('native', { strict: true, data: { random: rnd(43), sha256: null } }, (native) => {
			assert.match(contains({ ok: false }), pkce.pair(native));
		});
	});
});
