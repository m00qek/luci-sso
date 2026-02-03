import { test, assert, assert_eq } from 'testing';
import * as crypto from 'crypto';
import * as mbedtls from 'crypto_mbedtls';
import * as fixtures from 'fixtures';

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
    assert_eq(crypto.b64url_decode(" "), null, "Should return null for invalid characters");
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
    let payload = crypto.verify_jwt(fixtures.RS256.JWT_TOKEN, fixtures.RS256.JWT_PUBKEY);
    assert(payload, "JWT should be verified successfully");
    assert_eq(payload.sub, "1234567890", "Payload subject should match");
    assert_eq(payload.name, "John Doe", "Payload name should match");

    assert(!crypto.verify_jwt(fixtures.RS256.JWT_TOKEN + "x", fixtures.RS256.JWT_PUBKEY), "Should fail with tampered JWT");
});

test('ES256: Low-level Primitive', () => {
    let sig_bin = crypto.b64url_decode(fixtures.ES256.SIG_HELLO_B64URL);
    assert(mbedtls.verify_es256(fixtures.ES256.MSG, sig_bin, fixtures.ES256.PUBKEY), "Should verify valid ES256 signature");
});

test('ES256: Tampering', () => {
    let sig_bin = crypto.b64url_decode(fixtures.ES256.SIG_HELLO_B64URL);
    assert(!mbedtls.verify_es256(fixtures.ES256.MSG + "!", sig_bin, fixtures.ES256.PUBKEY), "Should fail on message tampering");
    
    // Flip a bit in the signature
    assert(!mbedtls.verify_es256(fixtures.ES256.MSG, "invalid_signature", fixtures.ES256.PUBKEY), "Should fail on signature tampering");
});

// =============================================================================
// Coverage / Security Policy Tests
// =============================================================================

test('Policy: Expired Token', () => {
    let payload = crypto.verify_jwt(fixtures.POLICY.JWT_EXPIRED, fixtures.POLICY.PUBKEY);
    assert_eq(payload, null, "Should reject expired token");
});

test('Policy: Future Token (nbf)', () => {
    let payload = crypto.verify_jwt(fixtures.POLICY.JWT_FUTURE, fixtures.POLICY.PUBKEY);
    assert_eq(payload, null, "Should reject token not yet valid (nbf)");
});

test('High-level verify_jwt (ES256)', () => {
    let payload = crypto.verify_jwt(fixtures.ES256.JWT_TOKEN, fixtures.ES256.PUBKEY);
    assert(payload, "Should verify valid ES256 JWT");
    assert_eq(payload.sub, "es256", "Subject should match");
    assert_eq(payload.name, "ES256 User", "Name should match");
});

test('Algorithm Mismatch (HS256)', () => {
    // Header: {"alg":"HS256","typ":"JWT"}
    let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; 
    let payload = "eyJzdWIiOiIxMjMifQ"; // {"sub":"123"}
    let sig = "signature_ignored";
    let jwt = header + "." + payload + "." + sig;
    
    // Pass RS256 key (irrelevant as alg check should fail first)
    assert_eq(crypto.verify_jwt(jwt, fixtures.RS256.PUBKEY), null, "Should reject unsupported algorithm HS256");
});

test('Malformed JWTs', () => {
    assert_eq(crypto.verify_jwt("header.payload", fixtures.RS256.PUBKEY), null, "Should reject truncated JWT");
    assert_eq(crypto.verify_jwt("garbage", fixtures.RS256.PUBKEY), null, "Should reject garbage string");
    assert_eq(crypto.verify_jwt(null, fixtures.RS256.PUBKEY), null, "Should handle null input safely");
    
    // Invalid JSON in header
    // "not_json" base64url encoded -> "bm90X2pzb24"
    let bad_json_jwt = "bm90X2pzb24.eyJzdWIiOiIxMjMifQ.sig";
    assert_eq(crypto.verify_jwt(bad_json_jwt, fixtures.RS256.PUBKEY), null, "Should reject invalid JSON header");
});
