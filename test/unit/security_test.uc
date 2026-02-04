import { test, assert, assert_eq } from 'testing';
import * as crypto from 'luci_sso.crypto';
import * as fixtures from 'fixtures';

test('Security: JWT - Reject alg: none attack', () => {
	// Header: {"alg":"none","typ":"JWT"}
	let bad_header = crypto.b64url_encode(sprintf("%J", { alg: "none", typ: "JWT" }));
	let payload = crypto.b64url_encode(sprintf("%J", { sub: "admin" }));
	let token = bad_header + "." + payload + "."; // No signature

	// Should be rejected because options.alg is required and must match
	let result = crypto.verify_jwt(token, "some-key", { alg: "RS256" });
	assert_eq(result.error, "ALGORITHM_MISMATCH", "Should reject alg: none mismatch");
});

test('Security: JWS - Reject alg: none attack', () => {
	let bad_header = crypto.b64url_encode(sprintf("%J", { alg: "none", typ: "JWT" }));
	let payload = crypto.b64url_encode(sprintf("%J", { sub: "admin" }));
	let token = bad_header + "." + payload + ".";

	let result = crypto.verify_jws(token, "secret");
	assert_eq(result.error, "UNSUPPORTED_ALGORITHM", "Should reject alg: none in JWS");
});

test('Security: JWT - Reject stripped signature', () => {
	let parts = split(fixtures.RS256.JWT_TOKEN, ".");
	let stripped = parts[0] + "." + parts[1] + ".";
	
	let result = crypto.verify_jwt(stripped, fixtures.RS256.JWT_PUBKEY, { alg: "RS256" });
	assert_eq(result.error, "INVALID_SIGNATURE_ENCODING", "Should reject stripped signature");
});

test('Security: Key Confusion - Reject RSA key used as HMAC secret', () => {
	let rsa_token = fixtures.RS256.JWT_TOKEN;
	let rsa_pubkey = fixtures.RS256.JWT_PUBKEY;
	
	let result = crypto.verify_jws(rsa_token, rsa_pubkey);
	assert_eq(result.error, "UNSUPPORTED_ALGORITHM", "Should reject RS256 token in HS256 verify");
});

test('Security: Integrity - Reject malformed JSON in signed payload', () => {
	let secret = "secret";
	let bad_payload = crypto.b64url_encode("{ invalid json }");
	
	let good_token = crypto.sign_jws({foo: "bar"}, secret);
	let parts = split(good_token, ".");
	let tampered_token = parts[0] + "." + bad_payload + "." + parts[2];
	
	let result = crypto.verify_jws(tampered_token, secret);
	assert_eq(result.error, "INVALID_SIGNATURE", "Tampering with payload should invalidate signature");
});