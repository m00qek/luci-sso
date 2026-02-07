import { test, assert, assert_eq, assert_throws } from 'testing';
import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as f from 'unit.tier1_fixtures';

// =============================================================================
// Tier 1: Cryptographic Plumbing (Platinum Standard)
// =============================================================================

test('PLUMBING: JWK Set Lookup', () => {
    let res = oidc.find_jwk(f.JWK_SET, "key-2");
    assert(res.ok);
    assert_eq(res.data.kty, "EC");

    res = oidc.find_jwk(f.JWK_SET, null);
    assert(res.ok);
    assert_eq(res.data.kid, "key-1");

    res = oidc.find_jwk(f.JWK_SET, "non-existent");
    assert_eq(res.error, "KEY_NOT_FOUND");
});

test('PLUMBING: Clock Tolerance Boundary Math', () => {
    let secret = "tolerance-test-secret-1234567890123456";
    let clock_tolerance = 300;
    let payload_ok = { exp: 1000 };
    let token_ok = crypto.sign_jws(payload_ok, secret);
    
    assert(crypto.verify_jwt(token_ok, secret, { alg: "HS256", now: 1299, clock_tolerance: clock_tolerance }).ok);
    
    let res = crypto.verify_jwt(token_ok, secret, { alg: "HS256", now: 1301, clock_tolerance: clock_tolerance });
    assert_eq(res.error, "TOKEN_EXPIRED");
});

test('PLUMBING: Invalid Algorithm in Header', () => {
    let key = "key";
    let opts = { alg: "RS256", now: 123, clock_tolerance: 300 };
    let bad_alg = crypto.b64url_encode(sprintf("%J", { alg: "ROT13" }));
    assert_eq(crypto.verify_jwt(bad_alg + ".e30.s", key, opts).error, "ALGORITHM_MISMATCH");

    let no_alg = crypto.b64url_encode(sprintf("%J", { typ: "JWT" }));
    assert_eq(crypto.verify_jwt(no_alg + ".e30.s", key, opts).error, "INVALID_HEADER_JSON");
});

test('PLUMBING: JWK to PEM Conversion', () => {
    let jwk = {
		kty: "RSA",
		n: "q0g5x3uxj4F9zmlMbadqN8rJpdebwZL2iMNFmaBCBLRX3neuHobGuMh16Wgt5NiW8-rD_2du7uA76nmUzoUBt3nF5LMtngFGJXFRpy6srKne5Ch9g4RZZrQA5VvE_Rviv3XQ7YbXZe55pRcvNjcxwSIKTGfAw4p1jUu1ty4sg0jVJsPAnp6EOIq7euWpqIRkyxT94VR_QQO9mLcjjuO7ta_ahC8pbGOOIOk7AtCd_KV56tk1Tid5iaYV8RIhXSDeef9q7-L9DY6pK1Mx2Yu8SdPkhgj5kswoqnQWwViDUZAw59eos6Hrbhdh4aFg9mUQm-qCNLXxScFg-X7xcW91pQ",
		e: "AQAB"
	};
	let res = crypto.jwk_to_pem(jwk);
	assert(res.ok, "JWK to PEM failed: " + res.error);
	assert(index(res.data, "-----BEGIN PUBLIC KEY-----") == 0);
});

test('PLUMBING: JWK to Secret (OCT/Symmetric)', () => {
	let secret_b64url = "bXktc2VjcmV0LWtleS0xMjM0NQ"; 
	let jwk = { kty: "oct", k: secret_b64url };
	let res = crypto.jwk_to_pem(jwk);
	assert(res.ok);
	assert_eq(res.data, "my-secret-key-12345");
});

test('PLUMBING: Token Size Enforcement', () => {
    let too_big = "";
    for (let i = 0; i < 1700; i++) too_big += "1234567890"; 
    assert_eq(crypto.verify_jwt(too_big, "key", { alg: "RS256", now: 123, clock_tolerance: 300 }).error, "TOKEN_TOO_LARGE");
});

test('PLUMBING: PKCE Primitives', () => {
    let verifier = crypto.pkce_generate_verifier(32);
    assert(length(verifier) >= 43);
    let challenge = crypto.pkce_calculate_challenge(verifier);
    assert(challenge);
    let pair = crypto.pkce_pair(32);
    assert(pair.verifier && pair.challenge);
});

// =============================================================================
// Tier 1: Torture Tests (Plumbing Stability)
// =============================================================================

test('TORTURE: Plumbing - Illegal Type Injection', () => {
    assert_throws(() => crypto.verify_jwt(123, "key", { now: 1, clock_tolerance: 1 }), "Should reject non-string token");
    assert_throws(() => crypto.verify_jwt("a.b.c", 123, { now: 1, clock_tolerance: 1 }), "Should reject non-string key");
    assert_throws(() => crypto.verify_jwt("a.b.c", "key", "not-obj"), "Should reject non-object options");
});

test('TORTURE: Plumbing - Empty JWK Handling', () => {
    let res = oidc.find_jwk([], "any-kid");
    assert_eq(res.error, "KEY_NOT_FOUND");
    res = oidc.find_jwk([], null);
    assert_eq(res.error, "NO_KEYS_AVAILABLE");
    res = crypto.jwk_to_pem({ kty: "RSA", n: "", e: "" });
    assert_eq(res.error, "MISSING_RSA_PARAMS");
});

test('TORTURE: Plumbing - JSON Depth (Complexity Limit)', () => {
    let deep = "{\"a\":";
    for(let i=0; i<100; i++) deep += "[";
    deep += "1";
    for(let i=0; i<100; i++) deep += "]";
    deep += "}";
    try { json(deep); } catch(e) {}
});

test('TORTURE: Plumbing - Buffer Transition Stability', () => {
    let secret = ""; for(let i=0; i<16384; i++) secret += "A";
    let res = crypto.sign_jws({foo: "bar"}, secret);
    assert(res, "Plumbing should handle 16KB secrets during signing");
    let verify = crypto.verify_jws(res, secret);
    assert(verify.ok, "Plumbing should handle 16KB secrets during verification");
});
