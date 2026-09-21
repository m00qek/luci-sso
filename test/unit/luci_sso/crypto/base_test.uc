import { describe, it, prop, gen, assert, equals, not, contains, regex, has_length, mock, spy } from 'utest';
import * as base from 'luci_sso.crypto.base';

// `random` and `safe_id` fake `native` (data-first) to test wrapper logic only —
// forwarding, Result shaping, the length-validation guard, and error branches.
// CSPRNG quality / SHA-256 correctness live in test/native.
// `constant_time_eq` is pure ucode (no native) and is tested directly.

function unhex(h) {
	let s = '';
	for (let i = 0; i < length(h); i += 2) s += chr(hex(substr(h, i, 2)));
	return s;
}

const BYTES_32  = unhex('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
const DIGEST    = unhex('0011223344556677' + '8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677'); // 32 bytes
const DIGEST_ID = '0011223344556677'; // first 8 bytes → 16 hex chars

// ─── constant_time_eq (pure) ─────────────────────────────────────────────────

describe('crypto.base: constant_time_eq', () => {
	it('rejects non-string arguments', () => {
		for (let v in [null, 42, [], {}, true]) {
			assert.match(false, base.constant_time_eq(v, 'x'));
			assert.match(false, base.constant_time_eq('x', v));
		}
	});

	it('rejects both arguments simultaneously being non-strings', () => {
		assert.match(false, base.constant_time_eq(null, null));
		assert.match(false, base.constant_time_eq(42, 42));
	});

	it('rejects inputs exceeding 16 KB', () => {
		let over = '';
		for (let i = 0; i < 16385; i++) over += 'a';
		assert.match(false, base.constant_time_eq(over, over));
		assert.match(false, base.constant_time_eq('short', over));
	});

	it('accepts the 16 KB boundary', () => {
		let at_limit = '';
		for (let i = 0; i < 16384; i++) at_limit += 'a';
		assert.match(true, base.constant_time_eq(at_limit, at_limit));
	});

	it('empty strings are equal', () => {
		assert.match(true, base.constant_time_eq('', ''));
	});

	it('non-empty string differs from empty', () => {
		assert.match(false, base.constant_time_eq('a', ''));
		assert.match(false, base.constant_time_eq('', 'a'));
	});

	it('binary strings with identical bytes are equal', () => {
		let s = '\x00\x01\x7f\xff';
		assert.match(true, base.constant_time_eq(s, s));
	});

	it('binary strings differing by one bit return false', () => {
		assert.match(false, base.constant_time_eq('\x00\x01\x02\xff', '\x00\x01\x02\xfe'));
	});

	prop('reflexivity: eq(s, s) is always true', gen.string({ max_len: 200 }), (s, ctx) => {
		ctx.classify('empty', length(s) === 0);
		ctx.classify('long (≥100)', length(s) >= 100);
		assert.match(true, base.constant_time_eq(s, s));
	});

	prop('symmetry: eq(a, b) == eq(b, a)',
		gen.tuple(gen.string({ max_len: 80 }), gen.string({ max_len: 80 })),
		(pair, ctx) => {
			let a = pair[0];
			let b = pair[1];
			ctx.classify('same length', length(a) === length(b));
			ctx.classify('equal strings', a === b);
			assert.match(base.constant_time_eq(b, a), base.constant_time_eq(a, b));
		}
	);

	prop('appending any byte breaks equality', gen.string({ max_len: 100 }), (s) => {
		assert.match(false, base.constant_time_eq(s, s + '\x00'));
		assert.match(false, base.constant_time_eq(s, s + '\xff'));
	});

	prop('distinct strings of same length are not equal',
		gen.bind(gen.int(1, 80), (n) =>
			gen.map(
				gen.tuple(gen.string({ len: n }), gen.string({ len: n })),
				(pair) => ({ a: pair[0], b: pair[1], distinct: pair[0] != pair[1] })
			)
		),
		(v) => {
			if (!v.distinct) return;
			assert.match(false, base.constant_time_eq(v.a, v.b));
		}
	);
});

// ─── random (wrapper over native.random) ─────────────────────────────────────

describe('crypto.base: random', () => {
	it('forwards the requested length to native.random and wraps the bytes', () => {
		mock.inject('native', { strict: true, data: { random: BYTES_32 } }, (native) => {
			let res = base.random(native, 32);
			assert.match(contains({ ok: true, data: BYTES_32 }), res);
			assert.match(32, spy(native).calls.random[0][0]);
		});
	});

	it('defaults to a 32-byte request when len is omitted', () => {
		mock.inject('native', { strict: true, data: { random: BYTES_32 } }, (native) => {
			assert.match(contains({ ok: true, data: has_length(32) }), base.random(native));
			assert.match(32, spy(native).calls.random[0][0]);
		});
	});

	it('returns CSPRNG_FAILURE when native.random returns null', () => {
		mock.inject('native', { strict: true, data: { random: null } }, (native) => {
			assert.match(contains({ ok: false, error: 'CSPRNG_FAILURE' }), base.random(native, 16));
		});
	});

	it('returns CSPRNG_FAILURE when native.random returns fewer bytes than requested', () => {
		mock.inject('native', { strict: true, data: { random: unhex('aabb') } }, (native) => {
			assert.match(contains({ ok: false, error: 'CSPRNG_FAILURE' }), base.random(native, 32));
		});
	});

	it('dies on a non-integer length', () => {
		mock.inject('native', { strict: true }, (native) => {
			assert.throws(() => base.random(native, 'bad'));
			assert.throws(() => base.random(native, 1.5));
		});
	});
});

// ─── safe_id (wrapper over native.sha256) ────────────────────────────────────

describe('crypto.base: safe_id', () => {
	it('returns [INVALID] for null, non-string, or <8-char input without calling native', () => {
		mock.inject('native', { strict: true }, (native) => {
			for (let v in [null, 42, [], {}, true, '', 'a', 'abcdefg'])
				assert.match('[INVALID]', base.safe_id(native, v));
		});
	});

	it('returns [ERROR] when native.sha256 fails', () => {
		mock.inject('native', { strict: true, data: { sha256: null } }, (native) => {
			assert.match('[ERROR]', base.safe_id(native, 'valid-token-input'));
		});
	});

	it('returns the first 8 digest bytes as 16 lowercase hex chars', () => {
		mock.inject('native', { strict: true, data: { sha256: DIGEST } }, (native) => {
			let id = base.safe_id(native, 'some-valid-token');
			assert.match(DIGEST_ID, id);
			assert.match('some-valid-token', spy(native).calls.sha256[0][0]);
		});
	});

	prop('any string ≥ 8 chars produces a 16-char hex id',
		gen.string({ min_len: 8, max_len: 200 }),
		(s, ctx) => {
			ctx.classify('exactly 8 chars', length(s) === 8);
			mock.inject('native', { strict: true, data: { sha256: DIGEST } }, (native) => {
				assert.match(regex(/^[0-9a-f]{16}$/), base.safe_id(native, s));
			});
		}
	);

	prop('any string < 8 chars always yields [INVALID]',
		gen.string({ max_len: 7 }),
		(s, ctx) => {
			ctx.classify('empty', length(s) === 0);
			mock.inject('native', { strict: true }, (native) => {
				assert.match('[INVALID]', base.safe_id(native, s));
			});
		}
	);
});
