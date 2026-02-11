import { test, assert, assert_eq } from 'testing';
import * as native from 'luci_sso.native';

test('native: torture - SHA256 boundary inputs', () => {
    assert(native.sha256(""), "Should handle empty string");
    
    let large = "1234567890";
    for (let i = 0; i < 17; i++) {
        large += large;
    }
    assert(native.sha256(large), "Should handle large input without crash");
});

test('native: torture - HMAC-SHA256 invalid inputs', () => {
    assert_eq(native.hmac_sha256(null, "msg"), null);
    assert_eq(native.hmac_sha256("key", null), null);
    assert_eq(native.hmac_sha256(123, "msg"), null);
});

test('native: torture - asymmetric malformed PEM', () => {
    let msg = "test";
    let sig = "garbage-sig";
    let bad_pem = "-----BEGIN PUBLIC KEY-----\nNOT-A-KEY\n-----END PUBLIC KEY-----";
    
    assert_eq(native.verify_rs256(msg, sig, bad_pem), false, "Malformed RSA PEM must fail gracefully");
    assert_eq(native.verify_es256(msg, sig, bad_pem), false, "Malformed EC PEM must fail gracefully");
});

test('native: torture - ES256 invalid signature length', () => {
    let key = "-----BEGIN PUBLIC KEY-----\n..."; 
    assert_eq(native.verify_es256("msg", "short", key), false, "Must reject short EC signatures");
});

test('native: torture - insecure RSA exponents', () => {
    // e = 0 or e = 1 are mathematically invalid/insecure for RSA
    // Native should return null/false for these.
    assert_eq(native.jwk_rsa_to_pem("n-bin", "\x00"), null, "Must reject exponent 0");
    assert_eq(native.jwk_rsa_to_pem("n-bin", "\x01"), null, "Must reject exponent 1");
});

test('native: torture - oversized parameter buffers', () => {
    let huge = "A";
    for (let i = 0; i < 14; i++) huge += huge; // ~16KB
    
    // Test if jwk_to_pem helpers handle oversized binary inputs without crash
    assert_eq(native.jwk_rsa_to_pem(huge, "AQAB"), null, "Reject oversized modulus");
    assert_eq(native.jwk_ec_p256_to_pem(huge, huge), null, "Reject oversized EC coordinates");
});

test('native: torture - random boundary lengths', () => {
    assert_eq(native.random(0), null, "Zero length should return null");
    assert_eq(native.random(-1), null, "Negative length should return null");
    assert_eq(native.random(5000), null, "Oversized request should return null");
});
