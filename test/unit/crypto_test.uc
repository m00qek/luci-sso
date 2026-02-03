import { test, assert, assert_eq } from 'testing';
import * as crypto from 'crypto';
import * as mbedtls from 'crypto_mbedtls';
import * as fixtures from 'fixtures';

// Helper to check success
function assert_success(result, msg) {
    if (result.error) {
        die(`${msg || "Expected success"} - Error: ${result.error}`);
    }
    assert(result.payload, msg);
}

// Helper to check failure
function assert_error(result, expected_err, msg) {
    if (!result.error) {
        die(`${msg || "Expected failure"} - Got success`);
    }
    assert_eq(result.error, expected_err, msg);
}

test('Base64URL: Character mapping', () => {
    assert_eq(crypto.b64url_decode("c3ViamVjdHM_X2lucHV0cw"), "subjects?_inputs", "Should map '-' and '_' correctly");
});

test('Base64URL: Padding variations', () => {
    assert_eq(crypto.b64url_decode("YQ"), "a", "Should handle 2-byte missing padding");
    assert_eq(crypto.b64url_decode("YWI"), "ab", "Should handle 1-byte missing padding");
    assert_eq(crypto.b64url_decode("YWJj"), "abc", "Should handle no missing padding");
    assert_eq(crypto.b64url_decode("YWJjZA"), "abcd", "Should handle multiple blocks");
});

test('Base64URL: Boundary cases', () => {
    assert_eq(crypto.b64url_decode(""), "", "Should handle empty string");
    assert_eq(crypto.b64url_decode(" "), null, "Should return null for invalid characters (space)");
    assert_eq(crypto.b64url_decode("YQ@"), null, "Should return null for invalid characters (@)");
    assert_eq(crypto.b64url_decode("Y"), null, "Should return null for invalid length");
    assert_eq(crypto.b64url_decode(123), null, "Should return null for non-string types");
});

test('RS256: Low-level Primitive', () => {
    let sig_bin = crypto.b64url_decode(fixtures.RS256.SIG_B64URL);
    assert(mbedtls.verify_rs256(fixtures.RS256.MSG, sig_bin, fixtures.RS256.PUBKEY), "Low-level verify should work with binary sig");
});

test('RS256: Message Tampering', () => {
    let sig_bin = crypto.b64url_decode(fixtures.RS256.SIG_B64URL);
    assert(!mbedtls.verify_rs256(fixtures.RS256.MSG + "!", sig_bin, fixtures.RS256.PUBKEY), "Should fail if message is modified");
});

test('RS256: Key Integrity', () => {
    let sig_bin = crypto.b64url_decode(fixtures.RS256.SIG_B64URL);
    assert(!mbedtls.verify_rs256(fixtures.RS256.MSG, sig_bin, "not a pem key"), "Should fail with malformed PEM");
});

test('RS256: Type Safety', () => {
    assert(!mbedtls.verify_rs256(null, "sig", fixtures.RS256.PUBKEY), "Should handle null message");
    assert(!mbedtls.verify_rs256(fixtures.RS256.MSG, null, fixtures.RS256.PUBKEY), "Should handle null signature");
    assert(!mbedtls.verify_rs256(fixtures.RS256.MSG, "sig", null), "Should handle null key");
});

test('High-level verify_jwt (RS256)', () => {
    let result = crypto.verify_jwt(fixtures.RS256.JWT_TOKEN, fixtures.RS256.JWT_PUBKEY, { alg: "RS256" });
    assert_success(result, "JWT should be verified successfully");
    
    assert_eq(result.payload.sub, "1234567890", "Payload subject should match");
    assert_eq(result.payload.name, "John Doe", "Payload name should match");

    // Tampered (flip last char)
    let token = fixtures.RS256.JWT_TOKEN;
    let tampered = substr(token, 0, length(token)-1) + (substr(token, -1) == "A" ? "B" : "A");
    let bad_result = crypto.verify_jwt(tampered, fixtures.RS256.JWT_PUBKEY, { alg: "RS256" });
    assert_error(bad_result, "INVALID_SIGNATURE", "Should fail with tampered JWT");
});

test('ES256: Low-level Primitive', () => {
    let sig_bin = crypto.b64url_decode(fixtures.ES256.SIG_HELLO_B64URL);
    assert(mbedtls.verify_es256(fixtures.ES256.MSG, sig_bin, fixtures.ES256.PUBKEY), "Should verify valid ES256 signature");
});

test('ES256: Tampering', () => {
    let sig_bin = crypto.b64url_decode(fixtures.ES256.SIG_HELLO_B64URL);
    assert(!mbedtls.verify_es256(fixtures.ES256.MSG + "!", sig_bin, fixtures.ES256.PUBKEY), "Should fail on message tampering");
    
    assert(!mbedtls.verify_es256(fixtures.ES256.MSG, "invalid_signature", fixtures.ES256.PUBKEY), "Should fail on signature tampering");
});

// =============================================================================
// Coverage / Security Policy Tests
// =============================================================================

test('Policy: Expired Token', () => {
    let result = crypto.verify_jwt(fixtures.POLICY.JWT_EXPIRED, fixtures.POLICY.PUBKEY, { alg: "RS256" });
    assert_error(result, "TOKEN_EXPIRED", "Should reject expired token");
});

test('Policy: Future Token (nbf)', () => {
    let result = crypto.verify_jwt(fixtures.POLICY.JWT_FUTURE, fixtures.POLICY.PUBKEY, { alg: "RS256" });
    assert_error(result, "TOKEN_NOT_YET_VALID", "Should reject token not yet valid (nbf)");
});

test('Policy: Clock Skew Configuration', () => {
    let original_time = global.time;
    global.time = function() { return 1500000100; }; // 100s after expiry

    try {
        let res1 = crypto.verify_jwt(fixtures.POLICY.JWT_EXPIRED, fixtures.POLICY.PUBKEY, { alg: "RS256" });
        assert_success(res1, "Should pass expired token within default skew window");

        let res2 = crypto.verify_jwt(fixtures.POLICY.JWT_EXPIRED, fixtures.POLICY.PUBKEY, { alg: "RS256", skew: 50 });
        assert_error(res2, "TOKEN_EXPIRED", "Should reject expired token outside custom skew window");
        
        global.time = original_time;
    } catch (e) {
        global.time = original_time;
        die("Test failed with exception: " + e);
    }
});

test('Policy: Algorithm Enforcement', () => {
    let result = crypto.verify_jwt(fixtures.RS256.JWT_TOKEN, fixtures.RS256.JWT_PUBKEY, { alg: "ES256" });
    assert_error(result, "ALGORITHM_MISMATCH", "Should reject if alg does not match option");
});

test('Policy: Algorithm Mismatch (HS256)', () => {
    let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; 
    let payload = "eyJzdWIiOiIxMjMifQ"; 
    let jwt = header + "." + payload + ".sig";
    let result = crypto.verify_jwt(jwt, fixtures.RS256.JWT_PUBKEY, { alg: "RS256" });
    assert_error(result, "ALGORITHM_MISMATCH", "Should reject mismatch");
});

test('Policy: Issuer and Audience', () => {
    let res1 = crypto.verify_jwt(fixtures.POLICY.JWT_WITH_CLAIMS, fixtures.POLICY.CLAIMS_PUBKEY, { 
        alg: "RS256",
        iss: "my-auth-server",
        aud: "my-app"
    });
    assert_success(res1, "Should pass with correct iss and aud");

    let res2 = crypto.verify_jwt(fixtures.POLICY.JWT_WITH_CLAIMS, fixtures.POLICY.CLAIMS_PUBKEY, { 
        alg: "RS256",
        iss: "other-server"
    });
    assert_error(res2, "ISSUER_MISMATCH", "Should reject wrong issuer");

    let res3 = crypto.verify_jwt(fixtures.POLICY.JWT_WITH_CLAIMS, fixtures.POLICY.CLAIMS_PUBKEY, { 
        alg: "RS256",
        aud: "other-app"
    });
    assert_error(res3, "AUDIENCE_MISMATCH", "Should reject wrong audience");
});

test('Policy: Missing Options', () => {
    let res1 = crypto.verify_jwt(fixtures.RS256.JWT_TOKEN, fixtures.RS256.JWT_PUBKEY);
    assert_error(res1, "MISSING_ALGORITHM_OPTION", "Should fail if options missing");
});

test('High-level verify_jwt (ES256)', () => {
    let result = crypto.verify_jwt(fixtures.ES256.JWT_TOKEN, fixtures.ES256.PUBKEY, { alg: "ES256" });
    assert_success(result, "Should verify valid ES256 JWT");
    assert_eq(result.payload.sub, "es256", "Subject should match");
});

test('Malformed JWTs', () => {
    assert_error(crypto.verify_jwt("header.payload", fixtures.RS256.PUBKEY, {alg:"RS256"}), "MALFORMED_JWT");
    assert_error(crypto.verify_jwt(null, fixtures.RS256.PUBKEY, {alg:"RS256"}), "TOKEN_NOT_STRING");
    
    let bad_json_jwt = "bm90X2pzb24.eyJzdWIiOiIxMjMifQ.sig";
    assert_error(crypto.verify_jwt(bad_json_jwt, fixtures.RS256.PUBKEY, {alg:"RS256"}), "INVALID_HEADER_JSON");
});

// =============================================================================
// PKCE / Utilities Tests
// =============================================================================

test('SHA-256', () => {
    let hash = crypto.sha256("hello");
    assert_eq(length(hash), 32, "SHA-256 hash must be 32 bytes");
    assert_eq(ord(substr(hash, 0, 1)), 0x2c, "SHA-256 hash value must match");
});

test('Random Generation', () => {
    let r1 = crypto.random(32);
    let r2 = crypto.random(32);
    assert_eq(length(r1), 32, "Random output must match requested length");
    assert(r1 != r2, "Random output must vary");
});

test('PKCE: Pair Generation', () => {
    let pair = crypto.pkce_pair(32);
    assert(pair.verifier, "Pair should have verifier");
    assert(pair.challenge, "Pair should have challenge");
    
    // Verify consistency
    let calc_challenge = crypto.pkce_calculate_challenge(pair.verifier);
    assert_eq(pair.challenge, calc_challenge, "Generated challenge must match calculated challenge");
});

test('PKCE: Official Test Vector', () => {
    // Verifier from RFC 7636 Appendix B
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    
    // Calculated challenge should match RFC
    let challenge = crypto.pkce_calculate_challenge(verifier);
    assert_eq(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "PKCE challenge must match RFC 7636 Appendix B");
});

test('PKCE: End-to-end flow', () => {
    let verifier = crypto.pkce_generate_verifier(32);
    assert(length(verifier) >= 43, "Verifier length should be at least 43 chars");
    
    let challenge = crypto.pkce_calculate_challenge(verifier);
    assert(length(challenge) == 43, "S256 Challenge should be 43 chars (32 bytes encoded)");
});