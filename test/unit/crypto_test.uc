import { test, assert, assert_eq } from 'testing';
import * as crypto from 'luci_sso.crypto';
import * as fixtures from 'fixtures';

// Helper to check success
function assert_success(result, msg) {
	if (!result.ok) {
		die(`${msg || "Expected success"} - Error: ${result.error}`);
	}
	if (result.data) {
		assert(result.data, msg);
	}
}

// Helper to check failure
function assert_error(result, expected_err, msg) {
	if (result.ok) {
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

test('High-level verify_jwt (RS256)', () => {
	let result = crypto.verify_jwt(fixtures.RS256.JWT_TOKEN, fixtures.RS256.JWT_PUBKEY, { alg: "RS256" });
	assert_success(result, "JWT should be verified successfully");
	assert_eq(result.data.sub, "1234567890");
});

test('JWS: Create and verify (HMAC-SHA256)', () => {
	let secret = "my-secret-key";
	let data = { user: "admin", role: "superuser" };
	
	let token = crypto.sign_jws(data, secret);
	assert(token, "Should create a JWS");
	let parts = split(token, ".");
	assert_eq(length(parts), 3, "JWS should have 3 parts");

	let result = crypto.verify_jws(token, secret);
	assert_success(result, "Should verify successfully");
	assert_eq(result.data.user, "admin");
	
	// Tamper
	let tampered = parts[0] + "." + parts[1] + "X" + "." + parts[2];
	let bad_result = crypto.verify_jws(tampered, secret);
	assert_error(bad_result, "INVALID_SIGNATURE", "Should reject tampered payload");
	
	// Wrong secret
	let wrong_secret = crypto.verify_jws(token, "wrong-secret");
	assert_error(wrong_secret, "INVALID_SIGNATURE", "Should reject wrong secret");

	// Unsupported Alg
	let bad_header = crypto.b64url_encode(sprintf("%J", { alg: "none" }));
	let bad_alg_token = bad_header + "." + parts[1] + "." + parts[2];
	let bad_alg_result = crypto.verify_jws(bad_alg_token, secret);
	assert_error(bad_alg_result, "UNSUPPORTED_ALGORITHM");
});

test('Random Generation wrapper', () => {
	let r1 = crypto.random(32);
	let r2 = crypto.random(32);
	assert_eq(length(r1), 32);
	assert(r1 != r2);
});

test('PKCE: Pair Generation', () => {
	let pair = crypto.pkce_pair(32);
	assert(pair.verifier);
	assert(pair.challenge);
	let calc_challenge = crypto.pkce_calculate_challenge(pair.verifier);
	assert_eq(pair.challenge, calc_challenge);
});

test('JWK to PEM (RSA)', () => {
	let result = crypto.jwk_to_pem(fixtures.JWK_RSA.JWK);
	assert_success(result, "Should convert RSA JWK to PEM");
	assert(index(result.data, "-----BEGIN PUBLIC KEY-----") == 0);
});

test('Contract: verify_jws die on bad types', () => {
	try {
		crypto.verify_jws(123, "secret");
		assert(false, "Should have died");
	} catch (e) {
		assert(index(e, "CONTRACT_VIOLATION") >= 0);
	}
});