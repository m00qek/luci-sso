import { describe, it, prop, gen, assert, equals, not, contains, has_length, regex } from 'utest';
import * as native from 'luci_sso.native';
import * as encoding from 'luci_sso.encoding';
import { PLUMBING_RSA } from 'tier1.fixtures';
import * as f0 from 'tier0.fixtures';
import { hex_to_bin, JWK_RSA, JWK_EC } from 'fixtures.native';

// ─── sha256 ──────────────────────────────────────────────────────────────────

describe('native: sha256', () => {
	it('known vector: "compliance-test"', () => {
		assert.match(hex_to_bin(f0.SHA256_STANDARD.hex), native.sha256(f0.SHA256_STANDARD.msg));
	});

	it('known vector: message with null bytes', () => {
		assert.match(hex_to_bin(f0.SHA256_NULL_BYTES.hex), native.sha256(f0.SHA256_NULL_BYTES.msg));
	});

	it('returns exactly 32 bytes', () => {
		assert.match(has_length(32), native.sha256('any input'));
	});

	it('returns null for null input', () => {
		assert.match(null, native.sha256(null));
	});

	it('returns null for non-string input', () => {
		assert.match(null, native.sha256(42));
	});

	it('is deterministic', () => {
		assert.match(native.sha256('deterministic'), native.sha256('deterministic'));
	});

	it('distinct inputs produce distinct digests', () => {
		assert.match(not(equals(native.sha256('input-a'))), native.sha256('input-b'));
	});

	prop('always produces 32 bytes for any string input', gen.string({ max_len: 200 }), (s, ctx) => {
		ctx.classify('empty', length(s) === 0);
		assert.match(has_length(32), native.sha256(s));
	});
});

// ─── hmac_sha256 ─────────────────────────────────────────────────────────────

describe('native: hmac_sha256', () => {
	it('known vector: standard key and message', () => {
		assert.match(hex_to_bin(f0.HMAC_STANDARD.hex), native.hmac_sha256(f0.HMAC_STANDARD.key, f0.HMAC_STANDARD.msg));
	});

	it('known vector: null bytes in key and message', () => {
		assert.match(hex_to_bin(f0.HMAC_NULL_BYTES.hex), native.hmac_sha256(f0.HMAC_NULL_BYTES.key, f0.HMAC_NULL_BYTES.msg));
	});

	it('known vector: leading zero bytes in key', () => {
		assert.match(hex_to_bin(f0.HMAC_LEADING_ZEROS.hex), native.hmac_sha256(f0.HMAC_LEADING_ZEROS.key, f0.HMAC_LEADING_ZEROS.msg));
	});

	it('known vector: key longer than SHA-256 block size (100 bytes > 64)', () => {
		assert.match(hex_to_bin(f0.HMAC_LONG_KEY.hex), native.hmac_sha256(f0.HMAC_LONG_KEY.key, f0.HMAC_LONG_KEY.msg));
	});

	it('returns exactly 32 bytes', () => {
		assert.match(has_length(32), native.hmac_sha256('key', 'msg'));
	});

	it('returns null for null key', () => {
		assert.match(null, native.hmac_sha256(null, 'msg'));
	});

	it('returns null for null message', () => {
		assert.match(null, native.hmac_sha256('key', null));
	});

	it('returns null for an empty key', () => {
		assert.match(null, native.hmac_sha256('', 'msg'));
	});

	it('different keys produce different MACs for the same message', () => {
		assert.match(not(equals(native.hmac_sha256('key-a', 'msg'))), native.hmac_sha256('key-b', 'msg'));
	});

	it('different messages produce different MACs for the same key', () => {
		assert.match(not(equals(native.hmac_sha256('key', 'msg-a'))), native.hmac_sha256('key', 'msg-b'));
	});

	prop('always returns 32 bytes for any non-empty key and any message',
		gen.tuple(gen.string({ min_len: 1, max_len: 100 }), gen.string({ max_len: 200 })),
		(pair, ctx) => {
			ctx.classify('short key (≤8)',   length(pair[0]) <= 8);
			ctx.classify('long key (>64)',   length(pair[0]) > 64);
			ctx.classify('empty message',    length(pair[1]) === 0);
			assert.match(has_length(32), native.hmac_sha256(pair[0], pair[1]));
		}
	);
});

// ─── random ──────────────────────────────────────────────────────────────────

describe('native: random', () => {
	it('never returns null', () => {
		assert.match(not(equals(null)), native.random(32));
	});

	it('two calls with the same size produce different bytes', () => {
		assert.match(not(equals(native.random(32))), native.random(32));
	});

	prop('output length always equals request', gen.int(1, 256), (n, ctx) => {
		ctx.classify('≤32',  n <= 32);
		ctx.classify('>128', n > 128);
		assert.match(has_length(n), native.random(n));
	});
});

// ─── verify_rs256 ────────────────────────────────────────────────────────────

describe('native: verify_rs256', () => {
	it('accepts a valid RSA-2048 signature', () => {
		assert.match(true, native.verify_rs256(f0.RSA_2048.msg, hex_to_bin(f0.RSA_2048.sig_hex), f0.RSA_2048.pub));
	});

	it('accepts a valid RSA-2048 signature over a message with null bytes', () => {
		assert.match(true, native.verify_rs256(f0.RSA_NULL_MSG.msg, hex_to_bin(f0.RSA_NULL_MSG.sig_hex), f0.RSA_NULL_MSG.pub));
	});

	it('accepts a valid RSA-4096 signature', () => {
		assert.match(true, native.verify_rs256(f0.RSA_4096.msg, hex_to_bin(f0.RSA_4096.sig_hex), f0.RSA_4096.pub));
	});

	it('rejects a tampered signature (lowest bit of first byte flipped)', () => {
		let sig = hex_to_bin(f0.RSA_2048.sig_hex);
		let tampered = chr(ord(substr(sig, 0, 1)) ^ 1) + substr(sig, 1);
		assert.match(false, native.verify_rs256(f0.RSA_2048.msg, tampered, f0.RSA_2048.pub));
	});

	it('rejects a valid signature verified against the wrong key', () => {
		assert.match(false, native.verify_rs256(f0.RSA_2048.msg, hex_to_bin(f0.RSA_2048.sig_hex), f0.RSA_4096.pub));
	});

	it('rejects a valid signature for a different message', () => {
		assert.match(false, native.verify_rs256('wrong-message', hex_to_bin(f0.RSA_2048.sig_hex), f0.RSA_2048.pub));
	});

	it('returns false for a malformed PEM string', () => {
		assert.match(false, native.verify_rs256(f0.RSA_2048.msg, hex_to_bin(f0.RSA_2048.sig_hex), 'not-a-pem'));
	});
});

// ─── verify_es256 ────────────────────────────────────────────────────────────

describe('native: verify_es256', () => {
	it('accepts a valid EC P-256 signature', () => {
		assert.match(true, native.verify_es256(f0.EC_256.msg, hex_to_bin(f0.EC_256.sig_hex), f0.EC_256.pub));
	});

	it('accepts a valid EC signature over a message with null bytes', () => {
		assert.match(true, native.verify_es256(f0.EC_NULL_MSG.msg, hex_to_bin(f0.EC_NULL_MSG.sig_hex), f0.EC_NULL_MSG.pub));
	});

	it('accepts a signature with low-bit S component (malleability edge case)', () => {
		assert.match(true, native.verify_es256(f0.EC_256_LOW_BIT.msg, hex_to_bin(f0.EC_256_LOW_BIT.sig_hex), f0.EC_256_LOW_BIT.pub));
	});

	it('rejects a tampered signature (lowest bit of first byte flipped)', () => {
		let sig = hex_to_bin(f0.EC_256.sig_hex);
		let tampered = chr(ord(substr(sig, 0, 1)) ^ 1) + substr(sig, 1);
		assert.match(false, native.verify_es256(f0.EC_256.msg, tampered, f0.EC_256.pub));
	});

	it('rejects a valid signature for a different message', () => {
		assert.match(false, native.verify_es256('wrong-message', hex_to_bin(f0.EC_256.sig_hex), f0.EC_256.pub));
	});

	it('returns false for a malformed PEM string', () => {
		assert.match(false, native.verify_es256(f0.EC_256.msg, hex_to_bin(f0.EC_256.sig_hex), 'not-a-pem'));
	});
});

// ─── jwk_rsa_to_pem ──────────────────────────────────────────────────────────

describe('native: jwk_rsa_to_pem', () => {
	it('produces a PUBLIC KEY PEM header', () => {
		assert.match(regex(/^-----BEGIN PUBLIC KEY-----/), native.jwk_rsa_to_pem(JWK_RSA.n_bin, JWK_RSA.e_bin));
	});

	it('produced PEM validates the PLUMBING_RSA JWT signature', () => {
		let pem = native.jwk_rsa_to_pem(JWK_RSA.n_bin, JWK_RSA.e_bin);
		assert.match(not(equals(null)), pem);
		let parts = split(PLUMBING_RSA.token, '.');
		let sig = encoding.b64url_decode(parts[2]);
		assert.match(contains({ ok: true }), sig);
		assert.match(true, native.verify_rs256(`${parts[0]}.${parts[1]}`, sig.data, pem));
	});

	it('returns null for null arguments', () => {
		assert.match(null, native.jwk_rsa_to_pem(null, JWK_RSA.e_bin));
		assert.match(null, native.jwk_rsa_to_pem(JWK_RSA.n_bin, null));
	});
});

// ─── jwk_ec_p256_to_pem ──────────────────────────────────────────────────────

describe('native: jwk_ec_p256_to_pem', () => {
	it('produces a PUBLIC KEY PEM header', () => {
		assert.match(regex(/^-----BEGIN PUBLIC KEY-----/), native.jwk_ec_p256_to_pem(JWK_EC.x_bin, JWK_EC.y_bin));
	});

	it('produced PEM validates a known EC_256 signature', () => {
		let pem = native.jwk_ec_p256_to_pem(JWK_EC.x_bin, JWK_EC.y_bin);
		assert.match(not(equals(null)), pem);
		assert.match(true, native.verify_es256(f0.EC_256.msg, hex_to_bin(f0.EC_256.sig_hex), pem));
	});

	it('returns null for a coordinate with wrong length (P-256 requires 32 bytes)', () => {
		let short = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09';
		assert.match(null, native.jwk_ec_p256_to_pem(short, JWK_EC.y_bin));
		assert.match(null, native.jwk_ec_p256_to_pem(JWK_EC.x_bin, short));
	});

	it('returns null for an empty coordinate', () => {
		assert.match(null, native.jwk_ec_p256_to_pem('', JWK_EC.y_bin));
		assert.match(null, native.jwk_ec_p256_to_pem(JWK_EC.x_bin, ''));
	});

	it('returns null for null arguments', () => {
		assert.match(null, native.jwk_ec_p256_to_pem(null, JWK_EC.y_bin));
		assert.match(null, native.jwk_ec_p256_to_pem(JWK_EC.x_bin, null));
	});
});
