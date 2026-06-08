import { it, assert, truthy } from 'utest';
import * as native from 'luci_sso.native';
import * as f from 'tier0.fixtures';

// --- Helpers ---
function bin_to_hex(s) {
	let h = "";
	for (let i = 0; i < length(s); i++) {
		h += sprintf("%02x", ord(s, i));
	}
	return h;
}

function hex_to_bin(h) {
    let s = "";
    for (let i = 0; i < length(h); i += 2) {
        s += chr(hex(substr(h, i, 2)));
    }
    return s;
}

// =============================================================================
// Compliance Tests (Tier 0)
// =============================================================================

it('native: compliance - SHA256 standard message', () => {
	let res = native.sha256(f.SHA256_STANDARD.msg);
	assert.match(f.SHA256_STANDARD.hex, bin_to_hex(res), "Standard SHA256 must match OpenSSL");
});

it('native: compliance - HMAC-SHA256 standard message', () => {
	let res = native.hmac_sha256(f.HMAC_STANDARD.key, f.HMAC_STANDARD.msg);
	assert.match(f.HMAC_STANDARD.hex, bin_to_hex(res), "Standard HMAC-SHA256 must match OpenSSL");
});

it('native: compliance - SHA256 with embedded null bytes', () => {
	let res = native.sha256(f.SHA256_NULL_BYTES.msg);
	assert.match(f.SHA256_NULL_BYTES.hex, bin_to_hex(res), "SHA256 must process full length, ignoring null bytes");
});

it('native: compliance - HMAC-SHA256 with embedded null bytes', () => {
	let res = native.hmac_sha256(f.HMAC_NULL_BYTES.key, f.HMAC_NULL_BYTES.msg);
	assert.match(f.HMAC_NULL_BYTES.hex, bin_to_hex(res), "HMAC must process full length keys/msgs with nulls");
});

it('native: compliance - HMAC-SHA256 with leading zeros', () => {
	let res = native.hmac_sha256(f.HMAC_LEADING_ZEROS.key, f.HMAC_LEADING_ZEROS.msg);
	assert.match(f.HMAC_LEADING_ZEROS.hex, bin_to_hex(res), "HMAC must handle inputs starting with null bytes");
});

it('native: compliance - HMAC-SHA256 with oversized key (RFC 2104)', () => {
    // Key is 100 bytes (exceeds 64-byte block size). Must be hashed first.
	let res = native.hmac_sha256(f.HMAC_LONG_KEY.key, f.HMAC_LONG_KEY.msg);
	assert.match(f.HMAC_LONG_KEY.hex, bin_to_hex(res), "HMAC must handle keys longer than block size correctly");
});

it('native: compliance - RSA 2048-bit verification', () => {
	let sig = hex_to_bin(f.RSA_2048.sig_hex);
	let res = native.verify_rs256(f.RSA_2048.msg, sig, f.RSA_2048.pub);
	assert.match(truthy(), res, "Must support 2048-bit RSA keys with SHA256 (32-byte hash)");
});

it('native: compliance - RSA verification with embedded null bytes', () => {
	let sig = hex_to_bin(f.RSA_NULL_MSG.sig_hex);
	let res = native.verify_rs256(f.RSA_NULL_MSG.msg, sig, f.RSA_NULL_MSG.pub);
	assert.match(truthy(), res, "RSA hashing must respect message length and include null bytes");
});

it('native: compliance - RSA 4096-bit verification', () => {
	let sig = hex_to_bin(f.RSA_4096.sig_hex);
	let res = native.verify_rs256(f.RSA_4096.msg, sig, f.RSA_4096.pub);
	assert.match(truthy(), res, "Must support 4096-bit RSA keys");
});

it('native: compliance - ES256 verification', () => {
	let sig = hex_to_bin(f.EC_256.sig_hex);
	let res = native.verify_es256(f.EC_256.msg, sig, f.EC_256.pub);
	assert.match(truthy(), res, "ES256 verification must succeed with OpenSSL raw signature");
});

it('native: compliance - ES256 verification with embedded null bytes', () => {
	let sig = hex_to_bin(f.EC_NULL_MSG.sig_hex);
	let res = native.verify_es256(f.EC_NULL_MSG.msg, sig, f.EC_NULL_MSG.pub);
	assert.match(truthy(), res, "EC hashing must respect message length and include null bytes");
});

it('native: compliance - ES256 low-bit verification (leading zeros)', () => {
	let sig = hex_to_bin(f.EC_256_LOW_BIT.sig_hex);
	let res = native.verify_es256(f.EC_256_LOW_BIT.msg, sig, f.EC_256_LOW_BIT.pub);
	assert.match(truthy(), res, "ES256 must correctly handle signatures with leading zero bytes");
});

it('native: compliance - RSA signature trailing garbage', () => {
    let sig = hex_to_bin(f.RSA_2048.sig_hex) + "\xff";
    let res = native.verify_rs256(f.RSA_2048.msg, sig, f.RSA_2048.pub);
    assert.match(false, res, "Must reject RSA signature with trailing garbage");
});

it('native: compliance - EC signature trailing garbage', () => {
    let sig = hex_to_bin(f.EC_256.sig_hex) + "\x00";
    let res = native.verify_es256(f.EC_256.msg, sig, f.EC_256.pub);
    assert.match(false, res, "Must reject EC signature with trailing garbage");
});

it('native: compliance - cross-algorithm PEM rejection', () => {
    let res = native.verify_rs256(f.EC_256.msg, hex_to_bin(f.RSA_2048.sig_hex), f.EC_256.pub);
    assert.match(false, res, "Must reject EC public key passed to RSA verification");
});

it('native: compliance - negative verification (wrong message)', () => {
	let sig = hex_to_bin(f.RSA_2048.sig_hex);
	let res = native.verify_rs256("completely-different-msg", sig, f.RSA_2048.pub);
	assert.match(false, res, "Must fail if message is tampered");
});

it('native: compliance - negative verification (wrong key)', () => {
	let sig = hex_to_bin(f.RSA_2048.sig_hex);
	let res = native.verify_rs256(f.RSA_2048.msg, sig, f.RSA_4096.pub);
	assert.match(false, res, "Must fail if public key doesn't match signer");
});

it('native: compliance - random number generator', () => {
	let r1 = native.random(32);
	let r2 = native.random(32);
	assert.match(32, length(r1), "Must return requested length");
	assert.match(truthy(), r1 != r2, "Subsequent calls must be unique");
});

it('native: compliance - RSA reject small public exponents (e < 65537)', () => {
	// RSA Key with e=3 (unsafe)
	let n_b64 = "ALrjS_Z_X_unsafe_modulus_placeholder_";
	
	// e=3 is 0x03 (1 byte)
	let e3_b64 = "Aw";
	let res = native.jwk_rsa_to_pem(n_b64, e3_b64);
	assert.match(null, res, "Should return null (reject) for RSA e=3");

	// e=65535 is 0x00FFFF (unsafe)
	let e65535_b64 = "AP__";
	res = native.jwk_rsa_to_pem(n_b64, e65535_b64);
	assert.match(null, res, "Should return null (reject) for RSA e=65535");
});