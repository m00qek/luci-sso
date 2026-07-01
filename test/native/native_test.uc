import { describe, it, prop, gen, assert, equals, not, contains, has_length, truthy, falsy, regex, is_type } from 'utest';
import * as native from 'luci_sso.native';
import * as encoding from 'luci_sso.encoding';
import { PLUMBING_RSA } from 'tier1.fixtures';
import * as f0 from 'native.fixtures';
import { hex_to_bin, JWK_RSA, JWK_EC } from 'native.fixtures';

// ─────────────────────────────────────────────────────────────────────────────
// Conformance suite for the compiled `native` crypto extension (mod/*.c).
//
// This is the single gate for swapping crypto backends (mbedtls / wolfssl /
// openssl): it asserts the FFI contract of the seven exported functions —
// correctness against known-answer vectors, and the security/boundary controls
// enforced in native_common.c. It imports ONLY `luci_sso.native` (+ pure
// helpers/fixtures); it must never route through `luci_sso.crypto`.
//
// Contract constants (mod/native.h): MAX_INPUT_SIZE=16384, ES256 sig=64,
// EC coord=32, RSA min=2048 bits, exponent must be F4 (65537 / AQAB).
// ─────────────────────────────────────────────────────────────────────────────

const MAX_INPUT       = 16384;
const SHA256_EMPTY    = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

// A validly-signed 512-bit RSA key: the signature verifies mathematically, but
// native MUST reject it because 512 < NATIVE_RSA_MIN_BITS (2048).
const WEAK_RSA_PUB =
	"-----BEGIN PUBLIC KEY-----\n" +
	"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALKUJMgLRqyOe0qduWFM0bMxt8SvyZQs\n" +
	"2AyuPgvH0FdCMWpvH5yK0AR13gtJWtFfyxDCfFrBZ79JT7z7fs+StPUCAwEAAQ==\n" +
	"-----END PUBLIC KEY-----";
const WEAK_RSA_SIG = b64dec("NQIvIQu5i0YKhIwhsvCqrYeNqKxQTABrufd0ssfVn/JezIJL67hET6S0kCdAQKv4Fv/a4Hxwqtz6FxUTsq4F0A==");

// A second, unrelated valid P-256 public key — used to prove verify_es256 binds
// to the signing key (every EC_256* fixture shares one key, so a distinct key
// is needed for the wrong-key negative).
const EC_256_OTHER_PUB =
	"-----BEGIN PUBLIC KEY-----\n" +
	"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEzhN1r60isW+NrJob/nIlkL22nxv\n" +
	"LYytpZi6MtrnMfr+MXm1HiMuJXVzFOdrAv3Hj25MlU+UsVV8FLlqFyT0YQ==\n" +
	"-----END PUBLIC KEY-----";

// Builds a byte string of exactly `n` bytes.
function bytes(n) {
	let s = 'A';
	while (length(s) < n) s += s;
	return substr(s, 0, n);
}

// ─── sha256 ──────────────────────────────────────────────────────────────────

describe('native: sha256', () => {
	it('known vector: empty string', () => {
		assert.match(hex_to_bin(SHA256_EMPTY), native.sha256(''));
	});

	it('known vector: "compliance-test"', () => {
		assert.match(hex_to_bin(f0.SHA256_STANDARD.hex), native.sha256(f0.SHA256_STANDARD.msg));
	});

	it('known vector: processes full length past embedded null bytes', () => {
		assert.match(hex_to_bin(f0.SHA256_NULL_BYTES.hex), native.sha256(f0.SHA256_NULL_BYTES.msg));
	});

	it('known vector: RFC 7636 PKCE S256 (b64url(sha256(verifier)) == challenge)', () => {
		// RFC 7636 Appendix B. This anchors the S256 identity that crypto/pkce
		// relies on; the pkce wrapper is tested with a faked native, so this is
		// the sole spec-conformance check for the real verifier→challenge chain.
		const RFC7636_VERIFIER  = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
		const RFC7636_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
		assert.match(RFC7636_CHALLENGE, encoding.b64url_encode(native.sha256(RFC7636_VERIFIER)).data);
	});

	it('returns exactly 32 bytes', () => {
		assert.match(has_length(32), native.sha256('any input'));
	});

	it('is deterministic', () => {
		assert.match(native.sha256('deterministic'), native.sha256('deterministic'));
	});

	it('distinct inputs produce distinct digests', () => {
		assert.match(not(equals(native.sha256('input-a'))), native.sha256('input-b'));
	});

	it('returns null for null input', () => {
		assert.match(null, native.sha256(null));
	});

	it('returns null for non-string input', () => {
		assert.match(null, native.sha256(42));
	});

	it('accepts input at the 16 KB ceiling and rejects one byte over', () => {
		assert.match(has_length(32), native.sha256(bytes(MAX_INPUT)));
		assert.match(null,           native.sha256(bytes(MAX_INPUT) + 'A'));
	});

	prop('always produces 32 bytes for any string input', gen.string({ max_len: 400 }), (s, ctx) => {
		ctx.classify('empty', length(s) === 0);
		assert.match(has_length(32), native.sha256(s));
	});

	prop('is deterministic for any input', gen.string({ max_len: 400 }), (s) => {
		assert.match(native.sha256(s), native.sha256(s));
	});
});

// ─── hmac_sha256 ─────────────────────────────────────────────────────────────

describe('native: hmac_sha256', () => {
	it('known vector: standard key and message', () => {
		assert.match(hex_to_bin(f0.HMAC_STANDARD.hex), native.hmac_sha256(f0.HMAC_STANDARD.key, f0.HMAC_STANDARD.msg));
	});

	it('known vector: embedded null bytes in key and message', () => {
		assert.match(hex_to_bin(f0.HMAC_NULL_BYTES.hex), native.hmac_sha256(f0.HMAC_NULL_BYTES.key, f0.HMAC_NULL_BYTES.msg));
	});

	it('known vector: leading zero bytes in key', () => {
		assert.match(hex_to_bin(f0.HMAC_LEADING_ZEROS.hex), native.hmac_sha256(f0.HMAC_LEADING_ZEROS.key, f0.HMAC_LEADING_ZEROS.msg));
	});

	it('known vector: key longer than the SHA-256 block size (100 > 64)', () => {
		assert.match(hex_to_bin(f0.HMAC_LONG_KEY.hex), native.hmac_sha256(f0.HMAC_LONG_KEY.key, f0.HMAC_LONG_KEY.msg));
	});

	it('returns exactly 32 bytes', () => {
		assert.match(has_length(32), native.hmac_sha256('key', 'msg'));
	});

	it('accepts an empty message (valid HMAC)', () => {
		assert.match(has_length(32), native.hmac_sha256('key', ''));
	});

	it('is deterministic', () => {
		assert.match(native.hmac_sha256('key', 'msg'), native.hmac_sha256('key', 'msg'));
	});

	it('different keys produce different MACs for the same message', () => {
		assert.match(not(equals(native.hmac_sha256('key-a', 'msg'))), native.hmac_sha256('key-b', 'msg'));
	});

	it('different messages produce different MACs for the same key', () => {
		assert.match(not(equals(native.hmac_sha256('key', 'msg-a'))), native.hmac_sha256('key', 'msg-b'));
	});

	it('returns null for an empty key', () => {
		assert.match(null, native.hmac_sha256('', 'msg'));
	});

	it('returns null for null key or null message', () => {
		assert.match(null, native.hmac_sha256(null, 'msg'));
		assert.match(null, native.hmac_sha256('key', null));
	});

	it('returns null for non-string arguments', () => {
		assert.match(null, native.hmac_sha256(123, 'msg'));
		assert.match(null, native.hmac_sha256('key', 123));
	});

	it('accepts key and message at the 16 KB ceiling and rejects one byte over', () => {
		assert.match(has_length(32), native.hmac_sha256('k', bytes(MAX_INPUT)));
		assert.match(has_length(32), native.hmac_sha256(bytes(MAX_INPUT), 'm'));
		assert.match(null,           native.hmac_sha256('k', bytes(MAX_INPUT) + 'A'));
		assert.match(null,           native.hmac_sha256(bytes(MAX_INPUT) + 'A', 'm'));
	});

	prop('always returns 32 bytes for any non-empty key and any message',
		gen.tuple(gen.string({ min_len: 1, max_len: 100 }), gen.string({ max_len: 200 })),
		(pair, ctx) => {
			ctx.classify('short key (≤8)', length(pair[0]) <= 8);
			ctx.classify('long key (>64)', length(pair[0]) > 64);
			ctx.classify('empty message',  length(pair[1]) === 0);
			assert.match(has_length(32), native.hmac_sha256(pair[0], pair[1]));
		}
	);
});

// ─── random ──────────────────────────────────────────────────────────────────

describe('native: random', () => {
	it('returns the requested number of bytes', () => {
		assert.match(has_length(32), native.random(32));
	});

	it('honours the lower and upper valid bounds (1 and 4096)', () => {
		assert.match(has_length(1),    native.random(1));
		assert.match(has_length(4096), native.random(4096));
	});

	it('two calls of the same size produce different bytes', () => {
		assert.match(not(equals(native.random(32))), native.random(32));
	});

	it('defaults to 32 bytes for a non-integer or missing argument', () => {
		assert.match(has_length(32), native.random());
		assert.match(has_length(32), native.random(null));
		assert.match(has_length(32), native.random('nope'));
	});

	it('returns null for zero or negative lengths', () => {
		assert.match(null, native.random(0));
		assert.match(null, native.random(-1));
	});

	it('returns null for lengths above 4096', () => {
		assert.match(null, native.random(4097));
		assert.match(null, native.random(100000));
	});

	prop('output length always equals the request in [1,4096]', gen.int(1, 4096), (n, ctx) => {
		ctx.classify('≤32',  n <= 32);
		ctx.classify('>2048', n > 2048);
		assert.match(has_length(n), native.random(n));
	});

	prop('successive draws of the same size are unique', gen.int(16, 256), (n) => {
		assert.match(not(equals(native.random(n))), native.random(n));
	});
});

// ─── verify_rs256 ────────────────────────────────────────────────────────────

describe('native: verify_rs256', () => {
	it('accepts a valid RSA-2048 signature', () => {
		assert.match(true, native.verify_rs256(f0.RSA_2048.msg, hex_to_bin(f0.RSA_2048.sig_hex), f0.RSA_2048.pub));
	});

	it('accepts a valid signature over a message with embedded null bytes', () => {
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

	it('rejects a signature with trailing garbage', () => {
		assert.match(false, native.verify_rs256(f0.RSA_2048.msg, hex_to_bin(f0.RSA_2048.sig_hex) + '\xff', f0.RSA_2048.pub));
	});

	it('rejects a valid signature verified against the wrong key', () => {
		assert.match(false, native.verify_rs256(f0.RSA_2048.msg, hex_to_bin(f0.RSA_2048.sig_hex), f0.RSA_4096.pub));
	});

	it('rejects a valid signature for a different message', () => {
		assert.match(false, native.verify_rs256('wrong-message', hex_to_bin(f0.RSA_2048.sig_hex), f0.RSA_2048.pub));
	});

	it('rejects an EC public key (cross-algorithm confusion)', () => {
		assert.match(false, native.verify_rs256(f0.RSA_2048.msg, hex_to_bin(f0.RSA_2048.sig_hex), f0.EC_256.pub));
	});

	it('SECURITY: rejects a validly-signed but weak 512-bit RSA key', () => {
		assert.match(false, native.verify_rs256('test message', WEAK_RSA_SIG, WEAK_RSA_PUB));
	});

	it('returns false for a malformed PEM string', () => {
		assert.match(false, native.verify_rs256(f0.RSA_2048.msg, hex_to_bin(f0.RSA_2048.sig_hex), 'not-a-pem'));
	});

	it('returns false for an empty or non-string signature', () => {
		assert.match(false, native.verify_rs256(f0.RSA_2048.msg, '', f0.RSA_2048.pub));
		assert.match(false, native.verify_rs256(f0.RSA_2048.msg, null, f0.RSA_2048.pub));
	});

	it('returns false for non-string message or key', () => {
		assert.match(false, native.verify_rs256(null, hex_to_bin(f0.RSA_2048.sig_hex), f0.RSA_2048.pub));
		assert.match(false, native.verify_rs256(f0.RSA_2048.msg, hex_to_bin(f0.RSA_2048.sig_hex), null));
		assert.match(false, native.verify_rs256(42, hex_to_bin(f0.RSA_2048.sig_hex), f0.RSA_2048.pub));
	});

	it('rejects oversized message, signature, or key (>16 KB) without crashing', () => {
		let big = bytes(MAX_INPUT) + 'A';
		assert.match(false, native.verify_rs256(big, 'sig', 'key'));
		assert.match(false, native.verify_rs256('msg', big, 'key'));
		assert.match(false, native.verify_rs256('msg', 'sig', big));
	});

	prop('never accepts an arbitrary signature over the real message/key', gen.string({ max_len: 300 }), (sig, ctx) => {
		ctx.classify('len 256', length(sig) == 256);
		assert.match(false, native.verify_rs256(f0.RSA_2048.msg, sig, f0.RSA_2048.pub));
	});
});

// ─── verify_es256 ────────────────────────────────────────────────────────────

describe('native: verify_es256', () => {
	it('accepts a valid EC P-256 signature', () => {
		assert.match(true, native.verify_es256(f0.EC_256.msg, hex_to_bin(f0.EC_256.sig_hex), f0.EC_256.pub));
	});

	it('accepts a valid signature over a message with embedded null bytes', () => {
		assert.match(true, native.verify_es256(f0.EC_NULL_MSG.msg, hex_to_bin(f0.EC_NULL_MSG.sig_hex), f0.EC_NULL_MSG.pub));
	});

	it('accepts a signature whose S component has a leading zero byte', () => {
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

	it('rejects a valid signature verified against the wrong (but valid) P-256 key', () => {
		assert.match(false, native.verify_es256(f0.EC_256.msg, hex_to_bin(f0.EC_256.sig_hex), EC_256_OTHER_PUB));
	});

	it('rejects an RSA public key (cross-algorithm confusion)', () => {
		assert.match(false, native.verify_es256(f0.EC_256.msg, hex_to_bin(f0.EC_256.sig_hex), f0.RSA_2048.pub));
	});

	it('SECURITY: rejects any signature that is not exactly 64 bytes (R|S)', () => {
		let sig = hex_to_bin(f0.EC_256.sig_hex);           // 64 bytes
		assert.match(false, native.verify_es256(f0.EC_256.msg, substr(sig, 0, 63),  f0.EC_256.pub)); // 63
		assert.match(false, native.verify_es256(f0.EC_256.msg, sig + '\x00',        f0.EC_256.pub)); // 65
		assert.match(false, native.verify_es256(f0.EC_256.msg, 'short',             f0.EC_256.pub));
	});

	it('returns false for a malformed PEM string', () => {
		assert.match(false, native.verify_es256(f0.EC_256.msg, hex_to_bin(f0.EC_256.sig_hex), 'not-a-pem'));
	});

	it('returns false for non-string arguments', () => {
		assert.match(false, native.verify_es256(null, hex_to_bin(f0.EC_256.sig_hex), f0.EC_256.pub));
		assert.match(false, native.verify_es256(f0.EC_256.msg, hex_to_bin(f0.EC_256.sig_hex), null));
	});

	it('rejects an oversized message (>16 KB) without crashing', () => {
		assert.match(false, native.verify_es256(bytes(MAX_INPUT) + 'A', hex_to_bin(f0.EC_256.sig_hex), f0.EC_256.pub));
	});

	prop('never accepts an arbitrary signature over the real message/key', gen.string({ max_len: 128 }), (sig, ctx) => {
		ctx.classify('exactly 64 bytes', length(sig) == 64);
		ctx.classify('wrong length',     length(sig) != 64);
		assert.match(false, native.verify_es256(f0.EC_256.msg, sig, f0.EC_256.pub));
	});
});

// ─── jwk_rsa_to_pem ──────────────────────────────────────────────────────────

describe('native: jwk_rsa_to_pem', () => {
	it('produces a PUBLIC KEY PEM header', () => {
		assert.match(regex(/^-----BEGIN PUBLIC KEY-----/), native.jwk_rsa_to_pem(JWK_RSA.n_bin, JWK_RSA.e_bin));
	});

	it('produced PEM validates the PLUMBING_RSA JWT signature (round-trip)', () => {
		let pem = native.jwk_rsa_to_pem(JWK_RSA.n_bin, JWK_RSA.e_bin);
		assert.match(not(equals(null)), pem);
		let parts = split(PLUMBING_RSA.token, '.');
		let sig = encoding.b64url_decode(parts[2]);
		assert.match(contains({ ok: true }), sig);
		assert.match(true, native.verify_rs256(`${parts[0]}.${parts[1]}`, sig.data, pem));
	});

	it('SECURITY: accepts only the F4 exponent (65537 / AQAB)', () => {
		// e values that MUST be rejected: even, small, wrong-length, or non-F4.
		let bad = [
			'',                  // empty
			'\x01',              // 1
			'\x00',              // 0 (even)
			'\x02',              // 2 (even)
			'\x00\x01',          // wrong length (2 bytes)
			'\x01\x00\x00',      // 65536 (even)
			'\x01\x03\x05\x08',  // 4 bytes, ends even
			'\x00\x00\x03',      // 3 (via padded bytes) — not F4
		];
		for (let e in bad)
			assert.match(null, native.jwk_rsa_to_pem(JWK_RSA.n_bin, e), `exponent ${b64enc(e)} must be rejected`);

		// The one accepted exponent.
		assert.match(regex(/BEGIN PUBLIC KEY/), native.jwk_rsa_to_pem(JWK_RSA.n_bin, '\x01\x00\x01'));
	});

	it('returns null for null or non-string arguments', () => {
		assert.match(null, native.jwk_rsa_to_pem(null, JWK_RSA.e_bin));
		assert.match(null, native.jwk_rsa_to_pem(JWK_RSA.n_bin, null));
		assert.match(null, native.jwk_rsa_to_pem(42, JWK_RSA.e_bin));
	});

	it('returns null for an oversized modulus (>16 KB)', () => {
		assert.match(null, native.jwk_rsa_to_pem(bytes(MAX_INPUT) + 'A', JWK_RSA.e_bin));
	});
});

// ─── jwk_ec_p256_to_pem ──────────────────────────────────────────────────────

describe('native: jwk_ec_p256_to_pem', () => {
	it('produces a PUBLIC KEY PEM header', () => {
		assert.match(regex(/^-----BEGIN PUBLIC KEY-----/), native.jwk_ec_p256_to_pem(JWK_EC.x_bin, JWK_EC.y_bin));
	});

	it('produced PEM validates a known EC_256 signature (round-trip)', () => {
		let pem = native.jwk_ec_p256_to_pem(JWK_EC.x_bin, JWK_EC.y_bin);
		assert.match(not(equals(null)), pem);
		assert.match(true, native.verify_es256(f0.EC_256.msg, hex_to_bin(f0.EC_256.sig_hex), pem));
	});

	it('returns null when a coordinate is not exactly 32 bytes', () => {
		let short = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09';
		assert.match(null, native.jwk_ec_p256_to_pem(short, JWK_EC.y_bin));
		assert.match(null, native.jwk_ec_p256_to_pem(JWK_EC.x_bin, short));
		assert.match(null, native.jwk_ec_p256_to_pem('', JWK_EC.y_bin));
	});

	it('SECURITY: returns null for a well-formed-length point that is not on the curve', () => {
		assert.match(null, native.jwk_ec_p256_to_pem(bytes(32), bytes(32)));
	});

	it('returns null for null or non-string arguments', () => {
		assert.match(null, native.jwk_ec_p256_to_pem(null, JWK_EC.y_bin));
		assert.match(null, native.jwk_ec_p256_to_pem(JWK_EC.x_bin, null));
		assert.match(null, native.jwk_ec_p256_to_pem(42, JWK_EC.y_bin));
	});

	prop('returns null for any x coordinate whose length is not 32 bytes',
		gen.string({ max_len: 64 }),
		(x, ctx) => {
			if (length(x) == 32) return; // 32-byte length is covered by the on-curve tests
			ctx.classify('empty', length(x) == 0);
			assert.match(null, native.jwk_ec_p256_to_pem(x, JWK_EC.y_bin));
		}
	);
});
