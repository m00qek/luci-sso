import { test, assert, assert_eq } from 'testing';
import * as crypto from 'crypto';
import * as mbedtls from 'crypto_mbedtls';

const VALID_PUBKEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqk1WZcjtRvPjwcN3WMk2
CRGeP5oCjIPNNuo87E0BFT3UdbNsLx44B+yGosB/FhwY/hKV8bXAopmA46wirqd/
azZH4sjsWTQs1uhtRI6GxR5xnoIFV4gRrMkqGkRLMTCeUajsxGw/jMlEzmyDwW+t
/ZPu7POBeuH3ki+wog44uKU22zN+1iigpUmJpBjUpg/hxin9s4dKAUavCJmwd+Bu
KX1cOY5pjP9wx8iJvssyv9vwosxR47107HKokkbOOGxiMLToG6SiQbWfslRwgw+r
iyqg2OlAgir5e1C0Bcd/qnTgNf9Vkv6v+n1dsDaWz99s4/LHr3AiP4LIeSuiYNl3
XwIDAQAB
-----END PUBLIC KEY-----`;

const VALID_MSG = "hello world";
const VALID_SIG_B64URL = "A4WLYP1G7SK3zpg7Ni_le_B0LzUUu1uLbFu1HXAApX3hkUiQLl1c7PWqMe408RqK-MqBiTB3mqJ9fXY1Z937kamwY5ycD1gMhyhfa9CgqrLA6jTZojcCanKqu13GWhZCNB5QiGu8O_sY-CUew-F32yef6rrx896BkfiB7Tyovg_jhsXEPyGX_Yf3CCPfGcMcRf-2pFIX1pnulUPgxVVIbidAuJ1SHxNI7UA3xTJq9phR5B_pnbNay1aVp50ewnKQoGFJj9EabFBVMkeRUCON29ZSt9YgDd1-0swWrZWEI3g3J25fbuVQS5IrxvLOZcjRE5zuc9m8RB4zY4PrbLQwQA";

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
    let sig_bin = crypto.b64url_decode(VALID_SIG_B64URL);
    assert(mbedtls.verify_rs256(VALID_MSG, sig_bin, VALID_PUBKEY), "Low-level verify should work with binary sig");
});

test('RS256: Message Tampering', () => {
    let sig_bin = crypto.b64url_decode(VALID_SIG_B64URL);
    assert(!mbedtls.verify_rs256(VALID_MSG + "!", sig_bin, VALID_PUBKEY), "Should fail if message is modified");
});

test('RS256: Key Integrity', () => {
    let sig_bin = crypto.b64url_decode(VALID_SIG_B64URL);
    assert(!mbedtls.verify_rs256(VALID_MSG, sig_bin, "not a pem key"), "Should fail with malformed PEM");
});

test('RS256: Type Safety', () => {
    assert(!mbedtls.verify_rs256(null, "sig", VALID_PUBKEY), "Should handle null message");
    assert(!mbedtls.verify_rs256(VALID_MSG, null, VALID_PUBKEY), "Should handle null signature");
    assert(!mbedtls.verify_rs256(VALID_MSG, "sig", null), "Should handle null key");
});

test('High-level verify_jwt', () => {
    let jwt_pubkey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq0g5x3uxj4F9zmlMbadq
N8rJpdebwZL2iMNFmaBCBLRX3neuHobGuMh16Wgt5NiW8+rD/2du7uA76nmUzoUB
t3nF5LMtngFGJXFRpy6srKne5Ch9g4RZZrQA5VvE/Rviv3XQ7YbXZe55pRcvNjcx
wSIKTGfAw4p1jUu1ty4sg0jVJsPAnp6EOIq7euWpqIRkyxT94VR/QQO9mLcjjuO7
ta/ahC8pbGOOIOk7AtCd/KV56tk1Tid5iaYV8RIhXSDeef9q7+L9DY6pK1Mx2Yu8
SdPkhgj5kswoqnQWwViDUZAw59eos6Hrbhdh4aFg9mUQm+qCNLXxScFg+X7xcW91
pQIDAQAB
-----END PUBLIC KEY-----`;

    let jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.qtO-zazDyKOQa176gjZMLWufxHbXVev3uK_vjAhynRiFuLdtO7h2zBZg-SPqv-AQcNIw0gmuUdv36ba2-MaTQ5QV0GOiB7wJBFOH4u-CmcPhCmQ4Zojd8D8zuXVxhYOSgscRacirbk1K_UfTA6m4AoWkpoJaAMQhpMLBY8JgwC3rfRKqhOsCKvAO5nVeJvcfkbEM03k-hvLTpKjz_kRjijVeaxCN4fx1c4TXiDgc70xt--Vj_0-RGgIueuEttxwpArT7-4zx4_mnRnteGcJdEjHKUbt4QOBOS5f7j0MKjYkarzOiaf8ZqX0gUPBREQnmhXE7pAge9cv2C9OiIVm71w";

    let payload = crypto.verify_jwt(jwt, jwt_pubkey);
    assert(payload, "JWT should be verified successfully");
    assert_eq(payload.sub, "1234567890", "Payload subject should match");
    assert_eq(payload.name, "John Doe", "Payload name should match");

    assert(!crypto.verify_jwt(jwt + "x", jwt_pubkey), "Should fail with tampered JWT");
});