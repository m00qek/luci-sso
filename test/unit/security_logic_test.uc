import { test, assert, assert_eq } from 'testing';
import * as crypto from 'luci_sso.crypto';

// =============================================================================
// Tier 2: Security Enforcement Logic
// =============================================================================

test('LOGIC: Security - Reject alg: none', () => {
	let none_header = crypto.b64url_encode(sprintf("%J", { alg: "none", typ: "JWT" }));
	let payload = crypto.b64url_encode(sprintf("%J", { sub: "admin" }));
	let token = none_header + "." + payload + ".";

	// 1. JWT High-level
	let res = crypto.verify_jwt(token, "secret", { alg: "RS256", now: 123 });
	assert_eq(res.error, "ALGORITHM_MISMATCH");

	// 2. JWS Primitive
	res = crypto.verify_jws(token, "secret");
	assert_eq(res.error, "UNSUPPORTED_ALGORITHM");
});

test('LOGIC: Security - Reject Stripped Signature', () => {
    let header = crypto.b64url_encode(sprintf("%J", { alg: "HS256" }));
    let payload = crypto.b64url_encode(sprintf("%J", { sub: "admin" }));
    let stripped = header + "." + payload + ".";
    
    let res = crypto.verify_jwt(stripped, "secret", { alg: "HS256", now: 123 });
    assert_eq(res.error, "INVALID_SIGNATURE_ENCODING");
});

test('LOGIC: Security - Payload Integrity', () => {
	let secret = "secret";
	let good_token = crypto.sign_jws({foo: "bar"}, secret);
	let parts = split(good_token, ".");
    
    // Tamper with payload (malformed JSON)
	let bad_payload = crypto.b64url_encode("{ invalid json }");
	let tampered = parts[0] + "." + bad_payload + "." + parts[2];
	
	let res = crypto.verify_jws(tampered, secret);
	assert_eq(res.error, "INVALID_SIGNATURE", "Tampering must invalidate HMAC signature");
});
