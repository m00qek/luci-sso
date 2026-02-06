import { test, assert, assert_eq } from 'testing';
import * as native from 'luci_sso.native';
import * as f from 'unit.tier0_fixtures';

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

test('COMPLIANCE: SHA256 Standard Message', () => {
	let res = native.sha256(f.SHA256_STANDARD.msg);
	assert_eq(bin_to_hex(res), f.SHA256_STANDARD.hex, "Standard SHA256 must match OpenSSL");
});

test('COMPLIANCE: HMAC-SHA256 Standard Message', () => {
	let res = native.hmac_sha256(f.HMAC_STANDARD.key, f.HMAC_STANDARD.msg);
	assert_eq(bin_to_hex(res), f.HMAC_STANDARD.hex, "Standard HMAC-SHA256 must match OpenSSL");
});

test('COMPLIANCE: SHA256 with Embedded Null Bytes', () => {
	let res = native.sha256(f.SHA256_NULL_BYTES.msg);
	assert_eq(bin_to_hex(res), f.SHA256_NULL_BYTES.hex, "SHA256 must process full length, ignoring null bytes");
});

test('COMPLIANCE: HMAC-SHA256 with Embedded Null Bytes', () => {
	let res = native.hmac_sha256(f.HMAC_NULL_BYTES.key, f.HMAC_NULL_BYTES.msg);
	assert_eq(bin_to_hex(res), f.HMAC_NULL_BYTES.hex, "HMAC must process full length keys/msgs with nulls");
});

test('COMPLIANCE: HMAC-SHA256 with Leading Zeros', () => {
	let res = native.hmac_sha256(f.HMAC_LEADING_ZEROS.key, f.HMAC_LEADING_ZEROS.msg);
	assert_eq(bin_to_hex(res), f.HMAC_LEADING_ZEROS.hex, "HMAC must handle inputs starting with null bytes");
});

test('COMPLIANCE: HMAC-SHA256 with Oversized Key (RFC 2104)', () => {
    // Key is 100 bytes (exceeds 64-byte block size). Must be hashed first.
	let res = native.hmac_sha256(f.HMAC_LONG_KEY.key, f.HMAC_LONG_KEY.msg);
	assert_eq(bin_to_hex(res), f.HMAC_LONG_KEY.hex, "HMAC must handle keys longer than block size correctly");
});

test('COMPLIANCE: RSA 2048-bit Verification', () => {
	let sig = hex_to_bin(f.RSA_2048.sig_hex);
	let res = native.verify_rs256(f.RSA_2048.msg, sig, f.RSA_2048.pub);
	assert(res, "Must support 2048-bit RSA keys");
});

test('COMPLIANCE: RSA Verification with Embedded Null Bytes', () => {
	let sig = hex_to_bin(f.RSA_NULL_MSG.sig_hex);
	let res = native.verify_rs256(f.RSA_NULL_MSG.msg, sig, f.RSA_NULL_MSG.pub);
	assert(res, "RSA hashing must respect message length and include null bytes");
});

test('COMPLIANCE: RSA 4096-bit Verification', () => {
	let sig = hex_to_bin(f.RSA_4096.sig_hex);
	let res = native.verify_rs256(f.RSA_4096.msg, sig, f.RSA_4096.pub);
	assert(res, "Must support 4096-bit RSA keys");
});

test('COMPLIANCE: ES256 Verification', () => {
	let sig = hex_to_bin(f.EC_256.sig_hex);
	let res = native.verify_es256(f.EC_256.msg, sig, f.EC_256.pub);
	assert(res, "ES256 verification must succeed with OpenSSL raw signature");
});

test('COMPLIANCE: ES256 Verification with Embedded Null Bytes', () => {
	let sig = hex_to_bin(f.EC_NULL_MSG.sig_hex);
	let res = native.verify_es256(f.EC_NULL_MSG.msg, sig, f.EC_NULL_MSG.pub);
	assert(res, "EC hashing must respect message length and include null bytes");
});

test('COMPLIANCE: ES256 Low-Bit Verification (Leading Zeros)', () => {
	let sig = hex_to_bin(f.EC_256_LOW_BIT.sig_hex);
	let res = native.verify_es256(f.EC_256_LOW_BIT.msg, sig, f.EC_256_LOW_BIT.pub);
	assert(res, "ES256 must correctly handle signatures with leading zero bytes");
});

test('COMPLIANCE: RSA Signature Trailing Garbage', () => {
    let sig = hex_to_bin(f.RSA_2048.sig_hex) + "\xff";
    let res = native.verify_rs256(f.RSA_2048.msg, sig, f.RSA_2048.pub);
    assert_eq(res, false, "Must reject RSA signature with trailing garbage");
});

test('COMPLIANCE: EC Signature Trailing Garbage', () => {
    let sig = hex_to_bin(f.EC_256.sig_hex) + "\x00";
    let res = native.verify_es256(f.EC_256.msg, sig, f.EC_256.pub);
    assert_eq(res, false, "Must reject EC signature with trailing garbage");
});

test('COMPLIANCE: Cross-Algorithm PEM Rejection', () => {
    let res = native.verify_rs256(f.EC_256.msg, hex_to_bin(f.RSA_2048.sig_hex), f.EC_256.pub);
    assert_eq(res, false, "Must reject EC public key passed to RSA verification");
});

test('COMPLIANCE: Negative Verification (Wrong Message)', () => {
	let sig = hex_to_bin(f.RSA_2048.sig_hex);
	let res = native.verify_rs256("completely-different-msg", sig, f.RSA_2048.pub);
	assert_eq(res, false, "Must fail if message is tampered");
});

test('COMPLIANCE: Negative Verification (Wrong Key)', () => {
	let sig = hex_to_bin(f.RSA_2048.sig_hex);
	let res = native.verify_rs256(f.RSA_2048.msg, sig, f.RSA_4096.pub);
	assert_eq(res, false, "Must fail if public key doesn't match signer");
});

test('COMPLIANCE: Random Number Generator', () => {
	let r1 = native.random(32);
	let r2 = native.random(32);
	assert_eq(length(r1), 32, "Must return requested length");
	assert(r1 != r2, "Subsequent calls must be unique");
});