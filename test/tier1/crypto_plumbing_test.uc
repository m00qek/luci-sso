import { it, assert, truthy } from 'utest';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as pkce from 'luci_sso.crypto.pkce';
import * as native from 'luci_sso.native';
import * as oidc from 'luci_sso.oidc';
import * as Result from 'luci_sso.result';
import * as f from 'tier1.fixtures';
import * as f2 from 'tier2.fixtures';
import * as h from 'lib.helpers';

// =============================================================================
// Tier 1: Cryptographic Plumbing (Platinum Standard)
// =============================================================================

it('crypto: plumbing - JWK set lookup', () => {
    let res = oidc.find_jwk(f.JWK_SET, "key-2");
    assert.match(truthy(), Result.is(res));
    assert.match(truthy(), res.ok);
    assert.match("EC", res.data.kty);

    res = oidc.find_jwk(f.JWK_SET, null);
    assert.match(truthy(), Result.is(res));
    assert.match(truthy(), res.ok);
    assert.match("key-1", res.data.kid);

    res = oidc.find_jwk(f.JWK_SET, "non-existent");
    assert.match(truthy(), Result.is(res));
    assert.match("KEY_NOT_FOUND", res.error);
});

it('crypto: plumbing - clock tolerance boundary math', () => {
    let privkey = f2.MOCK_PRIVKEY;
    let pubkey = crypto.jwk_to_pem(f2.MOCK_JWK).data;
    let clock_tolerance = 300;
    
    // 1. Success case
    let payload_ok = { ...f2.MOCK_CLAIMS, exp: 1000 };
    let token_ok = h.generate_id_token(payload_ok, privkey, "RS256");
    let res_v = crypto.jwt_verify(token_ok, pubkey, { alg: "RS256", now: 1299, clock_tolerance: clock_tolerance, iss: "https://trusted.idp", aud: "luci-app" });
    assert.match(truthy(), Result.is(res_v));
    assert.match(truthy(), res_v.ok);

    // 2. Failure case (expired)
    let res = crypto.jwt_verify(token_ok, pubkey, { alg: "RS256", now: 1301, clock_tolerance: clock_tolerance, iss: "https://trusted.idp", aud: "luci-app" });
    assert.match(truthy(), Result.is(res));
    assert.match("TOKEN_EXPIRED", res.error);
});

it('crypto: plumbing - invalid algorithm in header', () => {
    let key = "key";
    let opts = { alg: "RS256", now: 123, clock_tolerance: 300, iss: "https://example.com", aud: "client" };
    let bad_alg = encoding.b64url_encode(sprintf("%J", { alg: "ROT13" })).data;
    let res1 = crypto.jwt_verify(bad_alg + ".e30.s", key, opts);
    assert.match(truthy(), Result.is(res1));
    assert.match("ALGORITHM_MISMATCH", res1.error);

    let no_alg = encoding.b64url_encode(sprintf("%J", { typ: "JWT" })).data;
    let res2 = crypto.jwt_verify(no_alg + ".e30.s", key, opts);
    assert.match(truthy(), Result.is(res2));
    assert.match("INVALID_HEADER_JSON", res2.error);
});

it('crypto: plumbing - JWK to PEM conversion', () => {
    let jwk = {
		kty: "RSA",
		n: "q0g5x3uxj4F9zmlMbadqN8rJpdebwZL2iMNFmaBCBLRX3neuHobGuMh16Wgt5NiW8-rD_2du7uA76nmUzoUBt3nF5LMtngFGJXFRpy6srKne5Ch9g4RZZrQA5VvE_Rviv3XQ7YbXZe55pRcvNjcxwSIKTGfAw4p1jUu1ty4sg0jVJsPAnp6EOIq7euWpqIRkyxT94VR_QQO9mLcjjuO7ta_ahC8pbGOOIOk7AtCd_KV56tk1Tid5iaYV8RIhXSDeef9q7-L9DY6pK1Mx2Yu8SdPkhgj5kswoqnQWwViDUZAw59eos6Hrbhdh4aFg9mUQm-qCNLXxScFg-X7xcW91pQ",
		e: "AQAB"
	};
	let res = crypto.jwk_to_pem(jwk);
    assert.match(truthy(), Result.is(res));
	assert.match(truthy(), res.ok, "JWK to PEM failed: " + res.error);
	assert.match(truthy(), index(res.data, "-----BEGIN PUBLIC KEY-----") == 0);
});

it('crypto: plumbing - JWK to secret (OCT/symmetric)', () => {
	let secret_b64url = "bXktc2VjcmV0LWtleS0xMjM0NQ"; 
	let jwk = { kty: "oct", k: secret_b64url };
	let res = crypto.jwk_to_pem(jwk);
    assert.match(truthy(), Result.is(res));
	assert.match(truthy(), res.ok);
	assert.match("my-secret-key-12345", res.data);
});

it('crypto: plumbing - token size enforcement', () => {
    let too_big = "1234567890";
    for (let i = 0; i < 11; i++) too_big += too_big; // 10 * 2^11 = 20,480 (> 16,384)
    let res = crypto.jwt_verify(too_big, "key", { alg: "RS256", now: 123, clock_tolerance: 300 });
    assert.match(truthy(), Result.is(res));
    assert.match("TOKEN_TOO_LARGE", res.error);
});

it('crypto: plumbing - PKCE primitives', () => {
    let res_v = pkce.generate_verifier(native, 32);
    assert.match(truthy(), Result.is(res_v));
    assert.match(truthy(), res_v.ok);
    assert.match(truthy(), length(res_v.data) >= 43);
    let challenge_res = pkce.calculate_challenge(native, res_v.data);
    assert.match(truthy(), challenge_res.ok);
    let res_p = crypto.pkce_pair(32);
    assert.match(truthy(), Result.is(res_p));
    assert.match(truthy(), res_p.ok);
    assert.match(truthy(), res_p.data.verifier && res_p.data.challenge);
});

it('crypto: plumbing - correlation ID stability (safe_id)', () => {
    let token = "sensitive-token-data-1234567890";
    let id = crypto.safe_id(token);
    assert.match(16, length(id), "Correlation ID MUST be 16 characters (64 bits)");
    assert.match(truthy(), match(id, /^[0-9a-f]+$/), "Correlation ID MUST be hex encoded");
    
    assert.match(crypto.safe_id(token), id, "Correlation ID MUST be deterministic");
    assert.match("[INVALID]", crypto.safe_id(null));
    assert.match("[INVALID]", crypto.safe_id("short"));
});

// =============================================================================
// Tier 1: Torture Tests (Plumbing Stability)
// =============================================================================

it('crypto: torture - illegal type injection', () => {
    assert.throws(() => crypto.jwt_verify(123, "key", { now: 1, clock_tolerance: 1 }), null, "Should reject non-string token");
    assert.throws(() => crypto.jwt_verify("a.b.c", 123, { now: 1, clock_tolerance: 1 }), null, "Should reject non-string key");
    assert.throws(() => crypto.jwt_verify("a.b.c", "key", "not-obj"), null, "Should reject non-object options");
});

it('crypto: torture - empty JWK handling', () => {
    let res1 = oidc.find_jwk([], "any-kid");
    assert.match(truthy(), Result.is(res1));
    assert.match("KEY_NOT_FOUND", res1.error);
    let res2 = oidc.find_jwk([], null);
    assert.match(truthy(), Result.is(res2));
    assert.match("NO_KEYS_AVAILABLE", res2.error);
    let res3 = crypto.jwk_to_pem({ kty: "RSA", n: "", e: "" });
    assert.match(truthy(), Result.is(res3));
    assert.match("MISSING_RSA_PARAMS", res3.error);
});

it('crypto: torture - JSON depth (complexity limit)', () => {
    let deep = "{\"a\":";
    for(let i=0; i<100; i++) deep += "[";
    deep += "1";
    for(let i=0; i<100; i++) deep += "]";
    deep += "}";
    try { json(deep); } catch(e) {}
});

it('crypto: torture - buffer transition stability', () => {
    let secret = ""; for(let i=0; i<16384; i++) secret += "A";
    let res = crypto.jws_sign({foo: "bar"}, secret);
    assert.match(truthy(), Result.is(res));
    assert.match(truthy(), res.ok, "Plumbing should handle 16KB secrets during signing");
    let verify = crypto.jws_verify(res.data, secret);
    assert.match(truthy(), Result.is(verify));
    assert.match(truthy(), verify.ok, "Plumbing should handle 16KB secrets during verification");
});

it('crypto: plumbing - issuer normalization (B3)', () => {
    let privkey = f2.MOCK_PRIVKEY;
    let pubkey = crypto.jwk_to_pem(f2.MOCK_JWK).data;
    let opts = { alg: "RS256", now: 1000, clock_tolerance: 300, iss: "https://idp.com", aud: "luci-app" };

    // 1. Success case: Identical strings
    let t1 = h.generate_id_token({ ...f2.MOCK_CLAIMS, iss: "https://idp.com" }, privkey, "RS256");
    let res1 = crypto.jwt_verify(t1, pubkey, opts);
    assert.match(truthy(), Result.is(res1));
    assert.match(truthy(), res1.ok, "Should pass with identical issuer strings");

    // 2. Trailing slash in token (Current Failure Path for B3)
    let t2 = h.generate_id_token({ ...f2.MOCK_CLAIMS, iss: "https://idp.com/" }, privkey, "RS256");
    let res2 = crypto.jwt_verify(t2, pubkey, opts);
    assert.match(truthy(), Result.is(res2));
    assert.match(truthy(), res2.ok, "Should pass with trailing slash in token iss claim: " + (res2.error || ""));

    // 3. Mixed case origin (Current Failure Path for B3)
    let t3 = h.generate_id_token({ ...f2.MOCK_CLAIMS, iss: "HTTPS://IDP.COM" }, privkey, "RS256");
    let res3 = crypto.jwt_verify(t3, pubkey, opts);
    assert.match(truthy(), Result.is(res3));
    assert.match(truthy(), res3.ok, "Should pass with mixed case in token iss claim: " + (res3.error || ""));

    // 4. Trailing slash in config
    let t4 = h.generate_id_token({ ...f2.MOCK_CLAIMS, iss: "https://idp.com" }, privkey, "RS256");
    let res4 = crypto.jwt_verify(t4, pubkey, { ...opts, iss: "https://idp.com/" });
    assert.match(truthy(), Result.is(res4));
    assert.match(truthy(), res4.ok, "Should pass with trailing slash in config iss: " + (res4.error || ""));
});
