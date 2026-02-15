import { test, assert, assert_eq, assert_throws } from 'testing';
import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as Result from 'luci_sso.result';
import * as f from 'unit.tier1_fixtures';
import * as f2 from 'unit.tier2_fixtures';
import * as h from 'unit.helpers';

// =============================================================================
// Tier 1: Cryptographic Plumbing (Platinum Standard)
// =============================================================================

test('crypto: plumbing - JWK set lookup', () => {
    let res = oidc.find_jwk(f.JWK_SET, "key-2");
    assert(Result.is(res));
    assert(res.ok);
    assert_eq(res.data.kty, "EC");

    res = oidc.find_jwk(f.JWK_SET, null);
    assert(Result.is(res));
    assert(res.ok);
    assert_eq(res.data.kid, "key-1");

    res = oidc.find_jwk(f.JWK_SET, "non-existent");
    assert(Result.is(res));
    assert_eq(res.error, "KEY_NOT_FOUND");
});

test('crypto: plumbing - clock tolerance boundary math', () => {
    let privkey = f2.MOCK_PRIVKEY;
    let pubkey = crypto.jwk_to_pem(f2.MOCK_JWK).data;
    let clock_tolerance = 300;
    
    // 1. Success case
    let payload_ok = { ...f2.MOCK_CLAIMS, exp: 1000 };
    let token_ok = h.generate_id_token(payload_ok, privkey, "RS256");
    let res_v = crypto.verify_jwt(token_ok, pubkey, { alg: "RS256", now: 1299, clock_tolerance: clock_tolerance });
    assert(Result.is(res_v));
    assert(res_v.ok);
    
    // 2. Failure case (expired)
    let res = crypto.verify_jwt(token_ok, pubkey, { alg: "RS256", now: 1301, clock_tolerance: clock_tolerance });
    assert(Result.is(res));
    assert_eq(res.error, "TOKEN_EXPIRED");
});

test('crypto: plumbing - invalid algorithm in header', () => {
    let key = "key";
    let opts = { alg: "RS256", now: 123, clock_tolerance: 300 };
    let bad_alg = crypto.b64url_encode(sprintf("%J", { alg: "ROT13" }));
    let res1 = crypto.verify_jwt(bad_alg + ".e30.s", key, opts);
    assert(Result.is(res1));
    assert_eq(res1.error, "ALGORITHM_MISMATCH");

    let no_alg = crypto.b64url_encode(sprintf("%J", { typ: "JWT" }));
    let res2 = crypto.verify_jwt(no_alg + ".e30.s", key, opts);
    assert(Result.is(res2));
    assert_eq(res2.error, "INVALID_HEADER_JSON");
});

test('crypto: plumbing - JWK to PEM conversion', () => {
    let jwk = {
		kty: "RSA",
		n: "q0g5x3uxj4F9zmlMbadqN8rJpdebwZL2iMNFmaBCBLRX3neuHobGuMh16Wgt5NiW8-rD_2du7uA76nmUzoUBt3nF5LMtngFGJXFRpy6srKne5Ch9g4RZZrQA5VvE_Rviv3XQ7YbXZe55pRcvNjcxwSIKTGfAw4p1jUu1ty4sg0jVJsPAnp6EOIq7euWpqIRkyxT94VR_QQO9mLcjjuO7ta_ahC8pbGOOIOk7AtCd_KV56tk1Tid5iaYV8RIhXSDeef9q7-L9DY6pK1Mx2Yu8SdPkhgj5kswoqnQWwViDUZAw59eos6Hrbhdh4aFg9mUQm-qCNLXxScFg-X7xcW91pQ",
		e: "AQAB"
	};
	let res = crypto.jwk_to_pem(jwk);
    assert(Result.is(res));
	assert(res.ok, "JWK to PEM failed: " + res.error);
	assert(index(res.data, "-----BEGIN PUBLIC KEY-----") == 0);
});

test('crypto: plumbing - JWK to secret (OCT/symmetric)', () => {
	let secret_b64url = "bXktc2VjcmV0LWtleS0xMjM0NQ"; 
	let jwk = { kty: "oct", k: secret_b64url };
	let res = crypto.jwk_to_pem(jwk);
    assert(Result.is(res));
	assert(res.ok);
	assert_eq(res.data, "my-secret-key-12345");
});

test('crypto: plumbing - token size enforcement', () => {
    let too_big = "1234567890";
    for (let i = 0; i < 11; i++) too_big += too_big; // 10 * 2^11 = 20,480 (> 16,384)
    let res = crypto.verify_jwt(too_big, "key", { alg: "RS256", now: 123, clock_tolerance: 300 });
    assert(Result.is(res));
    assert_eq(res.error, "TOKEN_TOO_LARGE");
});

test('crypto: plumbing - PKCE primitives', () => {
    let res_v = crypto.pkce_generate_verifier(32);
    assert(Result.is(res_v));
    assert(res_v.ok);
    assert(length(res_v.data) >= 43);
    let challenge = crypto.pkce_calculate_challenge(res_v.data);
    assert(challenge);
    let res_p = crypto.pkce_pair(32);
    assert(Result.is(res_p));
    assert(res_p.ok);
    assert(res_p.data.verifier && res_p.data.challenge);
});

test('crypto: plumbing - correlation ID stability (safe_id)', () => {
    let token = "sensitive-token-data-1234567890";
    let id = crypto.safe_id(token);
    assert_eq(length(id), 16, "Correlation ID MUST be 16 characters (64 bits)");
    assert(match(id, /^[0-9a-f]+$/), "Correlation ID MUST be hex encoded");
    
    assert_eq(id, crypto.safe_id(token), "Correlation ID MUST be deterministic");
    assert_eq(crypto.safe_id(null), "[INVALID]");
    assert_eq(crypto.safe_id("short"), "[INVALID]");
});

// =============================================================================
// Tier 1: Torture Tests (Plumbing Stability)
// =============================================================================

test('crypto: torture - illegal type injection', () => {
    assert_throws(() => crypto.verify_jwt(123, "key", { now: 1, clock_tolerance: 1 }), "Should reject non-string token");
    assert_throws(() => crypto.verify_jwt("a.b.c", 123, { now: 1, clock_tolerance: 1 }), "Should reject non-string key");
    assert_throws(() => crypto.verify_jwt("a.b.c", "key", "not-obj"), "Should reject non-object options");
});

test('crypto: torture - empty JWK handling', () => {
    let res1 = oidc.find_jwk([], "any-kid");
    assert(Result.is(res1));
    assert_eq(res1.error, "KEY_NOT_FOUND");
    let res2 = oidc.find_jwk([], null);
    assert(Result.is(res2));
    assert_eq(res2.error, "NO_KEYS_AVAILABLE");
    let res3 = crypto.jwk_to_pem({ kty: "RSA", n: "", e: "" });
    assert(Result.is(res3));
    assert_eq(res3.error, "MISSING_RSA_PARAMS");
});

test('crypto: torture - JSON depth (complexity limit)', () => {
    let deep = "{\"a\":";
    for(let i=0; i<100; i++) deep += "[";
    deep += "1";
    for(let i=0; i<100; i++) deep += "]";
    deep += "}";
    try { json(deep); } catch(e) {}
});

test('crypto: torture - buffer transition stability', () => {
    let secret = ""; for(let i=0; i<16384; i++) secret += "A";
    let res = crypto.sign_jws({foo: "bar"}, secret);
    assert(Result.is(res));
    assert(res.ok, "Plumbing should handle 16KB secrets during signing");
    let verify = crypto.verify_jws(res.data, secret);
    assert(Result.is(verify));
    assert(verify.ok, "Plumbing should handle 16KB secrets during verification");
});

test('crypto: plumbing - issuer normalization (B3)', () => {
    let privkey = f2.MOCK_PRIVKEY;
    let pubkey = crypto.jwk_to_pem(f2.MOCK_JWK).data;
    let opts = { alg: "RS256", now: 1000, clock_tolerance: 300, iss: "https://idp.com" };

    // 1. Success case: Identical strings
    let t1 = h.generate_id_token({ ...f2.MOCK_CLAIMS, iss: "https://idp.com" }, privkey, "RS256");
    let res1 = crypto.verify_jwt(t1, pubkey, opts);
    assert(Result.is(res1));
    assert(res1.ok, "Should pass with identical issuer strings");

    // 2. Trailing slash in token (Current Failure Path for B3)
    let t2 = h.generate_id_token({ ...f2.MOCK_CLAIMS, iss: "https://idp.com/" }, privkey, "RS256");
    let res2 = crypto.verify_jwt(t2, pubkey, opts);
    assert(Result.is(res2));
    assert(res2.ok, "Should pass with trailing slash in token iss claim: " + (res2.error || ""));

    // 3. Mixed case origin (Current Failure Path for B3)
    let t3 = h.generate_id_token({ ...f2.MOCK_CLAIMS, iss: "HTTPS://IDP.COM" }, privkey, "RS256");
    let res3 = crypto.verify_jwt(t3, pubkey, opts);
    assert(Result.is(res3));
    assert(res3.ok, "Should pass with mixed case in token iss claim: " + (res3.error || ""));

    // 4. Trailing slash in config
    let t4 = h.generate_id_token({ ...f2.MOCK_CLAIMS, iss: "https://idp.com" }, privkey, "RS256");
    let res4 = crypto.verify_jwt(t4, pubkey, { ...opts, iss: "https://idp.com/" });
    assert(Result.is(res4));
    assert(res4.ok, "Should pass with trailing slash in config iss: " + (res4.error || ""));
});
