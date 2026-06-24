import { describe, it, prop, gen, assert, equals, not, contains, regex, has_length } from 'utest';
import * as real_native from 'luci_sso.native';
import * as hash from 'luci_sso.crypto.hash';
import * as f0 from 'tier0.fixtures';
import { hex_to_bin } from 'fixtures.native';

const broken = { sha256: () => null };

// SHA-256 known vectors (verified with sha256sum and openssl dgst -sha256)
const VECTORS = [
	{ input: '',    hex: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
	{ input: 'abc', hex: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' },
];

// ─── sha256 ──────────────────────────────────────────────────────────────────

describe('crypto.hash: sha256', () => {
	it('rejects non-string input', () => {
		for (let v in [null, 42, [], {}]) {
			assert.match(contains({ ok: false, error: 'INVALID_ARGUMENT' }), hash.sha256(real_native, v));
		}
	});

	it('returns Result.ok with exactly 32 raw bytes for any string', () => {
		assert.match(contains({ ok: true, data: has_length(32) }), hash.sha256(real_native, 'hello'));
	});

	it('returns CRYPTO_ERROR when native.sha256 fails', () => {
		assert.match(contains({ ok: false, error: 'CRYPTO_ERROR' }), hash.sha256(broken, 'hello'));
	});

	it('is deterministic', () => {
		let a = hash.sha256(real_native, 'deterministic-input');
		let b = hash.sha256(real_native, 'deterministic-input');
		assert.match(contains({ ok: true }), a);
		assert.match(contains({ ok: true }), b);
		assert.match(a.data, b.data);
	});

	it('known vector: SHA256_STANDARD', () => {
		assert.match(
			contains({ ok: true, data: equals(hex_to_bin(f0.SHA256_STANDARD.hex)) }),
			hash.sha256(real_native, f0.SHA256_STANDARD.msg)
		);
	});

	it('known vector: SHA256_NULL_BYTES', () => {
		assert.match(
			contains({ ok: true, data: equals(hex_to_bin(f0.SHA256_NULL_BYTES.hex)) }),
			hash.sha256(real_native, f0.SHA256_NULL_BYTES.msg)
		);
	});

	it('distinct inputs produce distinct digests', () => {
		let a = hash.sha256(real_native, 'input-a');
		let b = hash.sha256(real_native, 'input-b');
		assert.match(contains({ ok: true }), a);
		assert.match(contains({ ok: true }), b);
		assert.match(not(equals(a.data)), b.data);
	});

	prop('always returns 32 bytes for any string input',
		gen.string({ max_len: 200 }),
		(s, ctx) => {
			ctx.classify('empty', length(s) === 0);
			assert.match(contains({ ok: true, data: has_length(32) }), hash.sha256(real_native, s));
		}
	);
});

// ─── sha256_hex ──────────────────────────────────────────────────────────────

describe('crypto.hash: sha256_hex', () => {
	it('rejects non-string input', () => {
		for (let v in [null, 42, [], {}]) {
			assert.match(contains({ ok: false }), hash.sha256_hex(real_native, v));
		}
	});

	it('returns a 64-character lowercase hex string', () => {
		assert.match(contains({ ok: true, data: regex(/^[0-9a-f]{64}$/) }), hash.sha256_hex(real_native, 'hello'));
	});

	it('returns CRYPTO_ERROR when native.sha256 fails', () => {
		assert.match(contains({ ok: false, error: 'CRYPTO_ERROR' }), hash.sha256_hex(broken, 'hello'));
	});

	it('is consistent with sha256 raw output', () => {
		let raw = hash.sha256(real_native, 'consistency-check');
		let hex = hash.sha256_hex(real_native, 'consistency-check');
		assert.match(contains({ ok: true }), raw);
		assert.match(contains({ ok: true }), hex);

		let expected = '';
		for (let i = 0; i < 32; i++)
			expected += sprintf('%02x', ord(raw.data, i));
		assert.match(expected, hex.data);
	});

	it('known vector: sha256_hex("")', () => {
		assert.match(contains({ ok: true, data: VECTORS[0].hex }), hash.sha256_hex(real_native, VECTORS[0].input));
	});

	it('known vector: sha256_hex("abc")', () => {
		assert.match(contains({ ok: true, data: VECTORS[1].hex }), hash.sha256_hex(real_native, VECTORS[1].input));
	});

	prop('always returns 64 lowercase hex chars for any string',
		gen.string({ max_len: 200 }),
		(s, ctx) => {
			ctx.classify('empty', length(s) === 0);
			assert.match(contains({ ok: true, data: regex(/^[0-9a-f]{64}$/) }), hash.sha256_hex(real_native, s));
		}
	);
});
