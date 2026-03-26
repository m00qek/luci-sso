import { test, assert, assert_eq } from 'testing';
import * as native from 'luci_sso.native';
import * as Result from 'luci_sso.result';

// =============================================================================
// Tier 1: Native Boundary Safety (16KB Hard Limit)
// =============================================================================

function generate_large(size) {
    let s = "12345678"; // 8 bytes
    while (length(s) * 2 <= size) {
        s += s;
    }
    if (length(s) < size) {
        s += substr(s, 0, size - length(s));
    }
    return s;
}

test('native: boundary - sha256 input limits', () => {
    const MAX = 16384;
    
    // 1. Exact Limit (16384)
    let data_ok = generate_large(MAX);
    let res_ok = native.sha256(data_ok);
    assert(res_ok != null, "Should accept exactly 16384 bytes");
    assert(length(res_ok) == 32, "Should return 32-byte hash");

    // 2. Over Limit (16385)
    let data_bad = data_ok + "A";
    let res_bad = native.sha256(data_bad);
    assert(res_bad == null, "Should reject 16385 bytes (Null return)");
});

test('native: boundary - hmac_sha256 input limits', () => {
    const MAX = 16384;
    let data_ok = generate_large(MAX);
    let key_ok = "secret";

    // 1. Data at limit
    let res_ok = native.hmac_sha256(key_ok, data_ok);
    assert(res_ok != null, "Should accept 16384 bytes data");

    // 2. Key at limit
    let res_key_ok = native.hmac_sha256(data_ok, "msg");
    assert(res_key_ok != null, "Should accept 16384 bytes key");

    // 3. Data over limit
    assert(native.hmac_sha256(key_ok, data_ok + "A") == null, "Should reject 16385 bytes data");

    // 4. Key over limit
    assert(native.hmac_sha256(data_ok + "A", "msg") == null, "Should reject 16385 bytes key");
});

test('native: boundary - verify_rs256 input limits', () => {
    const MAX = 16384;
    let data_ok = generate_large(MAX);
    let sig_ok = generate_large(256); // typical RS256 sig size
    let key_ok = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";

    // We don't need a VALID signature/key here, the boundary check in 
    // native_common.c happens BEFORE the crypto library is called.
    
    // 1. Msg over limit
    assert(native.verify_rs256(data_ok + "A", sig_ok, key_ok) === false, "Should return false for msg > 16KB");

    // 2. Sig over limit
    assert(native.verify_rs256(data_ok, data_ok + "A", key_ok) === false, "Should return false for sig > 16KB");

    // 3. Key over limit
    // Note: native.h has NATIVE_RSA_PEM_MAX (4096), but native_common.c 
    // uses NATIVE_MAX_INPUT_SIZE (16384) for the initial boundary check.
    assert(native.verify_rs256(data_ok, sig_ok, data_ok + "A") === false, "Should return false for key > 16KB");
});
