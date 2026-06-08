import * as native from 'luci_sso.native';
import * as crypto from 'luci_sso.crypto';
import { it, assert, truthy } from 'utest';

it('native: RSA hardening - reject invalid exponents (N2)', () => {
    // n is 1024-bit RSA modulus (minimal but valid for test)
    let n = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    
    let cases = [
        { name: "Even: 0", e: "\x00" },
        { name: "Even: 2", e: "\x02" },
        { name: "Even: 65536", e: "\x01\x00\x00" },
        { name: "Even: Multi-byte end with zero", e: "\x01\x03\x05\x08" },
        { name: "Small: 1", e: "\x01" },
        { name: "Empty", e: "" }
    ];

    for (let c in cases) {
        // jwk_rsa_to_pem(n, e) returns null on failure
        let res = native.jwk_rsa_to_pem(n, c.e);
        assert.match(truthy(), res === null, `Should reject invalid exponent: ${c.name}`);
    }
});

it('native: random - persistent DRBG (N1)', () => {
    // We can't easily prove it's persistent from here, 
    // but we can verify it still works and produces entropy.
    let r1 = native.random(32);
    let r2 = native.random(32);
    assert.match(truthy(), type(r1) == "string", "Native random must return a string");
    assert.match(truthy(), length(r1) == 32, "Native random must return requested length");
    assert.match(truthy(), r1 != r2, "Random results should be unique");
});

it('native: security - reject oversized inputs (B4)', () => {
    // 17KB exceeds the 16KB MAX_INPUT_SIZE
    let large_str = "";
    for (let i = 0; i < 17000; i++) large_str += "A";
    
    let dummy_key = "PEM";
    let dummy_sig = "SIG";
    
    // verify_rs256(msg, sig, key)
    assert.match(truthy(), native.verify_rs256(large_str, dummy_sig, dummy_key) === false, "Should reject oversized message");
    assert.match(truthy(), native.verify_rs256(dummy_sig, large_str, dummy_key) === false, "Should reject oversized signature");
    assert.match(truthy(), native.verify_rs256(dummy_sig, dummy_sig, large_str) === false, "Should reject oversized key");

    // verify_es256(msg, sig, key)
    assert.match(truthy(), native.verify_es256(large_str, dummy_sig, dummy_key) === false, "Should reject oversized message (EC)");

    // sha256(msg)
    assert.match(truthy(), native.sha256(large_str) === null, "Should reject oversized message in sha256 (W7)");

    // hmac_sha256(key, msg)
    assert.match(truthy(), native.hmac_sha256(large_str, "msg") === null, "Should reject oversized key in hmac_sha256 (W7)");
    assert.match(truthy(), native.hmac_sha256("key", large_str) === null, "Should reject oversized message in hmac_sha256 (W7)");
});
