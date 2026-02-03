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
    let sig_bin = crypto.b64url_decode(fixtures.RS256_SIG_B64URL);
    assert(mbedtls.verify_rs256(fixtures.RS256_MSG, sig_bin, fixtures.RS256_PUBKEY), "Low-level verify should work with binary sig");
});

test('RS256: Message Tampering', () => {
    let sig_bin = crypto.b64url_decode(fixtures.RS256_SIG_B64URL);
    assert(!mbedtls.verify_rs256(fixtures.RS256_MSG + "!", sig_bin, fixtures.RS256_PUBKEY), "Should fail if message is modified");
});

test('RS256: Key Integrity', () => {
    let sig_bin = crypto.b64url_decode(fixtures.RS256_SIG_B64URL);
    assert(!mbedtls.verify_rs256(fixtures.RS256_MSG, sig_bin, "not a pem key"), "Should fail with malformed PEM");
});

test('RS256: Type Safety', () => {
    assert(!mbedtls.verify_rs256(null, "sig", fixtures.RS256_PUBKEY), "Should handle null message");
    assert(!mbedtls.verify_rs256(fixtures.RS256_MSG, null, fixtures.RS256_PUBKEY), "Should handle null signature");
    assert(!mbedtls.verify_rs256(fixtures.RS256_MSG, "sig", null), "Should handle null key");
});

test('High-level verify_jwt (RS256)', () => {
    let result = crypto.verify_jwt(fixtures.RS256_JWT_TOKEN, fixtures.RS256_JWT_PUBKEY, { alg: "RS256" });
    assert_success(result, "JWT should be verified successfully");
    
    assert_eq(result.payload.sub, "1234567890", "Payload subject should match");
    assert_eq(result.payload.name, "John Doe", "Payload name should match");

    // Tampered (flip last char)
    let token = fixtures.RS256_JWT_TOKEN;
    let tampered = substr(token, 0, length(token)-1) + (substr(token, -1) == "A" ? "B" : "A");
    let bad_result = crypto.verify_jwt(tampered, fixtures.RS256_JWT_PUBKEY, { alg: "RS256" });
    assert_error(bad_result, "INVALID_SIGNATURE", "Should fail with tampered JWT");
});

test('ES256: Low-level Primitive', () => {
    let sig_bin = crypto.b64url_decode(fixtures.ES256_SIG_HELLO_B64URL);
    assert(mbedtls.verify_es256(fixtures.ES256_MSG, sig_bin, fixtures.ES256_PUBKEY), "Should verify valid ES256 signature");
});

test('ES256: Tampering', () => {
    let sig_bin = crypto.b64url_decode(fixtures.ES256_SIG_HELLO_B64URL);
    assert(!mbedtls.verify_es256(fixtures.ES256_MSG + "!", sig_bin, fixtures.ES256_PUBKEY), "Should fail on message tampering");
    
    // Flip a bit in the signature
    assert(!mbedtls.verify_es256(fixtures.ES256_MSG, "invalid_signature", fixtures.ES256_PUBKEY), "Should fail on signature tampering");
});

// =============================================================================
// Coverage / Security Policy Tests
// =============================================================================

test('Policy: Expired Token', () => {
    // Expired in 2017. Even with skew, it should fail.
    let result = crypto.verify_jwt(fixtures.JWT_EXPIRED, fixtures.COVERAGE_PUBKEY, { alg: "RS256" });
    assert_error(result, "TOKEN_EXPIRED", "Should reject expired token");
});

test('Policy: Future Token (nbf)', () => {
    // Valid in 2100. Should fail.
    let result = crypto.verify_jwt(fixtures.JWT_FUTURE, fixtures.COVERAGE_PUBKEY, { alg: "RS256" });
    assert_error(result, "TOKEN_NOT_YET_VALID", "Should reject token not yet valid (nbf)");
});

test('Policy: Clock Skew Configuration', () => {
    let original_time = global.time;
    // JWT_EXPIRED exp is 1500000000
    // We simulate time being 1500000100 (100 seconds "late")
    global.time = function() { return 1500000100; };

    try {
        // Default skew is 300s. 100s late is within window. Should PASS.
        let res1 = crypto.verify_jwt(fixtures.JWT_EXPIRED, fixtures.COVERAGE_PUBKEY, { alg: "RS256" });
        assert_success(res1, "Should pass expired token within default skew window");

        // Custom skew 50s. 100s late is OUTSIDE window. Should FAIL.
        let res2 = crypto.verify_jwt(fixtures.JWT_EXPIRED, fixtures.COVERAGE_PUBKEY, { alg: "RS256", skew: 50 });
        assert_error(res2, "TOKEN_EXPIRED", "Should reject expired token outside custom skew window");
        
        global.time = original_time;
    } catch (e) {
        global.time = original_time;
        die("Test failed with exception: " + e);
    }
});

test('Policy: Algorithm Enforcement', () => {
    // Token is RS256. We ask for ES256.
    let result = crypto.verify_jwt(fixtures.RS256_JWT_TOKEN, fixtures.RS256_JWT_PUBKEY, { alg: "ES256" });
    assert_error(result, "ALGORITHM_MISMATCH", "Should reject if alg does not match option");
});

test('Policy: Algorithm Mismatch (HS256)', () => {
    // Header: {"alg":"HS256","typ":"JWT"}
    let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; 
    let payload = "eyJzdWIiOiIxMjMifQ"; // {"sub":"123"}
    let sig = "signature_ignored";
    let jwt = header + "." + payload + "." + sig;
    
    // We expect RS256. Token is HS256.
    let result = crypto.verify_jwt(jwt, fixtures.RS256_JWT_PUBKEY, { alg: "RS256" });
    assert_error(result, "ALGORITHM_MISMATCH", "Should reject mismatch");
});

test('Policy: Issuer and Audience', () => {
    // Correct Iss/Aud
    let res1 = crypto.verify_jwt(fixtures.JWT_WITH_CLAIMS, fixtures.CLAIMS_PUBKEY, { 
        alg: "RS256",
        iss: "my-auth-server",
        aud: "my-app"
    });
    assert_success(res1, "Should pass with correct iss and aud");

    // Wrong Issuer
    let res2 = crypto.verify_jwt(fixtures.JWT_WITH_CLAIMS, fixtures.CLAIMS_PUBKEY, { 
        alg: "RS256",
        iss: "other-server",
        aud: "my-app"
    });
    assert_error(res2, "ISSUER_MISMATCH", "Should reject wrong issuer");

    // Wrong Audience
    let res3 = crypto.verify_jwt(fixtures.JWT_WITH_CLAIMS, fixtures.CLAIMS_PUBKEY, { 
        alg: "RS256",
        iss: "my-auth-server",
        aud: "other-app"
    });
    assert_error(res3, "AUDIENCE_MISMATCH", "Should reject wrong audience");
    
    // Missing options (defaults ignore check)
    let res4 = crypto.verify_jwt(fixtures.JWT_WITH_CLAIMS, fixtures.CLAIMS_PUBKEY, { 
        alg: "RS256"
    });
    assert_success(res4, "Should ignore iss/aud if not specified in options");
});

test('Policy: Missing Options', () => {
    let res1 = crypto.verify_jwt(fixtures.RS256_JWT_TOKEN, fixtures.RS256_JWT_PUBKEY);
    assert_error(res1, "MISSING_ALGORITHM_OPTION", "Should fail if options missing");
    
    let res2 = crypto.verify_jwt(fixtures.RS256_JWT_TOKEN, fixtures.RS256_JWT_PUBKEY, {});
    assert_error(res2, "MISSING_ALGORITHM_OPTION", "Should fail if alg missing");
});

test('High-level verify_jwt (ES256)', () => {
    let result = crypto.verify_jwt(fixtures.ES256_JWT_TOKEN, fixtures.ES256_PUBKEY, { alg: "ES256" });
    assert_success(result, "Should verify valid ES256 JWT");
    assert_eq(result.payload.sub, "es256", "Subject should match");
});

test('Malformed JWTs', () => {
    assert_error(crypto.verify_jwt("header.payload", fixtures.RS256_PUBKEY, {alg:"RS256"}), "MALFORMED_JWT");
    assert_error(crypto.verify_jwt("garbage", fixtures.RS256_PUBKEY, {alg:"RS256"}), "MALFORMED_JWT");
    assert_error(crypto.verify_jwt(null, fixtures.RS256_PUBKEY, {alg:"RS256"}), "TOKEN_NOT_STRING");
    
    let bad_json_jwt = "bm90X2pzb24.eyJzdWIiOiIxMjMifQ.sig";
    assert_error(crypto.verify_jwt(bad_json_jwt, fixtures.RS256_PUBKEY, {alg:"RS256"}), "INVALID_HEADER_JSON");
});
