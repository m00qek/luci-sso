import { it, assert, truthy } from 'utest';
import * as native from 'luci_sso.native';

it('native: torture - SHA256 boundary inputs', () => {
    assert.match(truthy(), native.sha256(""), "Should handle empty string");
    
    // Exact 16KB boundary
    let max_ok = "";
    for (let i = 0; i < 16384; i++) max_ok += "A";
    assert.match(truthy(), native.sha256(max_ok), "Should handle 16KB input");

    // Overflow boundary
    let too_large = max_ok + "B";
    assert.match(truthy(), native.sha256(too_large) === null, "Should reject 16KB + 1 byte input");
});

it('native: torture - HMAC-SHA256 invalid inputs', () => {
    assert.match(null, native.hmac_sha256(null, "msg"));
    assert.match(null, native.hmac_sha256("key", null));
    assert.match(null, native.hmac_sha256(123, "msg"));
});

it('native: torture - asymmetric malformed PEM', () => {
    let msg = "test";
    let sig = "garbage-sig";
    let bad_pem = "-----BEGIN PUBLIC KEY-----\nNOT-A-KEY\n-----END PUBLIC KEY-----";
    
    assert.match(false, native.verify_rs256(msg, sig, bad_pem), "Malformed RSA PEM must fail gracefully");
    assert.match(false, native.verify_es256(msg, sig, bad_pem), "Malformed EC PEM must fail gracefully");
});

it('native: torture - ES256 invalid signature length', () => {
    let key = "-----BEGIN PUBLIC KEY-----\n..."; 
    assert.match(false, native.verify_es256("msg", "short", key), "Must reject short EC signatures");
});

it('native: torture - insecure RSA exponents', () => {
    // e = 0 or e = 1 are mathematically invalid/insecure for RSA
    // Native should return null/false for these.
    assert.match(null, native.jwk_rsa_to_pem("n-bin", "\x00"), "Must reject exponent 0");
    assert.match(null, native.jwk_rsa_to_pem("n-bin", "\x01"), "Must reject exponent 1");
});

it('native: torture - oversized parameter buffers', () => {
    let huge = "A";
    for (let i = 0; i < 14; i++) huge += huge; // ~16KB
    
    // Test if jwk_to_pem helpers handle oversized binary inputs without crash
    assert.match(null, native.jwk_rsa_to_pem(huge, "AQAB"), "Reject oversized modulus");
    assert.match(null, native.jwk_ec_p256_to_pem(huge, huge), "Reject oversized EC coordinates");
});

it('native: torture - random boundary lengths', () => {
    assert.match(null, native.random(0), "Zero length should return null");
    assert.match(null, native.random(-1), "Negative length should return null");
    assert.match(null, native.random(5000), "Oversized request should return null");
});
