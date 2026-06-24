import { describe, it, prop, gen, assert, equals, not, contains, regex, has_length } from 'utest';
import * as real_native from 'luci_sso.native';
import * as base from 'luci_sso.crypto.base';

const broken = { sha256: () => null, random: () => null };
const liar   = { random: () => 'x' }; // always 1 byte regardless of request

// ─── constant_time_eq ────────────────────────────────────────────────────────

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

// ─── random ──────────────────────────────────────────────────────────────────

describe('crypto.base: random', () => {
	it('defaults to 32 bytes', () => {
		assert.match(contains({ ok: true, data: has_length(32) }), base.random(real_native));
	});

	it('returns the exact number of requested bytes', () => {
		for (let n in [1, 8, 16, 32, 64, 128]) {
			assert.match(contains({ ok: true, data: has_length(n) }), base.random(real_native, n), `wrong length for n=${n}`);
		}
	});

	it('returns CSPRNG_FAILURE when native.random returns null', () => {
		assert.match(contains({ ok: false, error: 'CSPRNG_FAILURE' }), base.random(broken, 16));
	});

	it('returns CSPRNG_FAILURE when native.random returns fewer bytes than requested', () => {
		assert.match(contains({ ok: false, error: 'CSPRNG_FAILURE' }), base.random(liar, 32));
	});

	it('dies on non-integer len', () => {
		assert.throws(() => base.random(real_native, 'bad'));
		assert.throws(() => base.random(real_native, 1.5));
	});

	it('two calls produce different bytes', () => {
		let a = base.random(real_native, 32);
		let b = base.random(real_native, 32);
		assert.match(contains({ ok: true }), a);
		assert.match(contains({ ok: true }), b);
		assert.match(not(equals(a.data)), b.data);
	});

	prop('output length always matches request',
		gen.int(1, 256),
		(n, ctx) => {
			ctx.classify('short (≤32)',   n <= 32);
			ctx.classify('medium (≤128)', n > 32 && n <= 128);
			ctx.classify('long (>128)',   n > 128);
			assert.match(contains({ ok: true, data: has_length(n) }), base.random(real_native, n));
		}
	);
});

// ─── safe_id ─────────────────────────────────────────────────────────────────

describe('crypto.base: safe_id', () => {
	it('returns [INVALID] for null', () => {
		assert.match('[INVALID]', base.safe_id(real_native, null));
	});

	it('returns [INVALID] for non-string types', () => {
		for (let v in [42, [], {}, true]) {
			assert.match('[INVALID]', base.safe_id(real_native, v));
		}
	});

	it('returns [INVALID] for strings shorter than 8 characters', () => {
		for (let s in ['', 'a', 'abcdefg']) {
			assert.match('[INVALID]', base.safe_id(real_native, s));
		}
	});

	it('accepts exactly 8 characters', () => {
		assert.match(regex(/^[0-9a-f]{16}$/), base.safe_id(real_native, '12345678'));
	});

	it('returns [ERROR] when native.sha256 fails', () => {
		assert.match('[ERROR]', base.safe_id(broken, 'valid-token-input'));
	});

	it('returns a 16-character lowercase hex string', () => {
		assert.match(regex(/^[0-9a-f]{16}$/), base.safe_id(real_native, 'some-valid-token'));
	});

	it('is deterministic for the same input', () => {
		let t = 'repeatable-token-value';
		assert.match(base.safe_id(real_native, t), base.safe_id(real_native, t));
	});

	it('different inputs produce different ids', () => {
		let a = base.safe_id(real_native, 'token-value-aaa');
		let b = base.safe_id(real_native, 'token-value-bbb');
		assert.match(not(equals(a)), b);
	});

	prop('any string ≥ 8 chars produces a 16-char hex id',
		gen.string({ min_len: 8, max_len: 200 }),
		(s, ctx) => {
			ctx.classify('exactly 8 chars', length(s) === 8);
			ctx.classify('long (>50)',      length(s) > 50);
			assert.match(regex(/^[0-9a-f]{16}$/), base.safe_id(real_native, s));
		}
	);

	prop('any string < 8 chars always yields [INVALID]',
		gen.string({ max_len: 7 }),
		(s, ctx) => {
			ctx.classify('empty', length(s) === 0);
			assert.match('[INVALID]', base.safe_id(real_native, s));
		}
	);
});
