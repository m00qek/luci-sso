import { describe, it, assert, contains, mock, spy } from 'utest';
import * as hash from 'luci_sso.crypto.hash';

// These tests fake `native` (via test/proxies/native.uc) so they exercise only
// the ucode wrapper logic — type guards, Result shaping, hex encoding, error
// branches. Crypto correctness (real SHA-256 vectors) lives in test/native.

// Raw bytes from hex (ucode '\xNN' literals ≥0x80 encode as UTF-8, so build
// digests with chr() to get genuine bytes).
function unhex(h) {
	let s = '';
	for (let i = 0; i < length(h); i += 2) s += chr(hex(substr(h, i, 2)));
	return s;
}

// A digest whose bytes exercise %02x formatting: 0x00 (leading zero),
// 0x0f (high-nibble zero), 0xa5, 0xff.
const FAKE_DIGEST_HEX = '000fa5ff';
const FAKE_DIGEST     = unhex(FAKE_DIGEST_HEX);

// ─── sha256 ──────────────────────────────────────────────────────────────────

describe('crypto.hash: sha256', () => {
	it('returns INVALID_ARGUMENT for non-string input without calling native', () => {
		mock.inject('native', { strict: true }, (native) => {
			for (let v in [null, 42, [], {}])
				assert.match(contains({ ok: false, error: 'INVALID_ARGUMENT' }), hash.sha256(native, v));
		});
	});

	it('forwards the input to native.sha256 and wraps the digest in Result.ok', () => {
		mock.inject('native', { strict: true, data: { sha256: FAKE_DIGEST } }, (native) => {
			let res = hash.sha256(native, 'hello');
			assert.match(contains({ ok: true, data: FAKE_DIGEST }), res);
			assert.match('hello', spy(native).calls.sha256[0][0]);
		});
	});

	it('maps a null native.sha256 result to CRYPTO_ERROR', () => {
		mock.inject('native', { strict: true, data: { sha256: null } }, (native) => {
			assert.match(contains({ ok: false, error: 'CRYPTO_ERROR' }), hash.sha256(native, 'hello'));
		});
	});
});

// ─── sha256_hex ──────────────────────────────────────────────────────────────

describe('crypto.hash: sha256_hex', () => {
	it('lowercase-hex-encodes the raw digest, preserving leading zeros', () => {
		mock.inject('native', { strict: true, data: { sha256: FAKE_DIGEST } }, (native) => {
			assert.match(contains({ ok: true, data: FAKE_DIGEST_HEX }), hash.sha256_hex(native, 'x'));
		});
	});

	it('propagates INVALID_ARGUMENT for non-string input', () => {
		mock.inject('native', { strict: true }, (native) => {
			assert.match(contains({ ok: false, error: 'INVALID_ARGUMENT' }), hash.sha256_hex(native, 42));
		});
	});

	it('propagates CRYPTO_ERROR when native.sha256 fails', () => {
		mock.inject('native', { strict: true, data: { sha256: null } }, (native) => {
			assert.match(contains({ ok: false, error: 'CRYPTO_ERROR' }), hash.sha256_hex(native, 'x'));
		});
	});
});
