import { test, assert, assert_eq } from 'testing';
import * as crypto from 'luci_sso.crypto';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

// =============================================================================
// Tier 2: Security Enforcement Logic
// =============================================================================

test('Security: JWT - Reject alg: none', () => {
	let none_header = crypto.b64url_encode(sprintf("%J", { alg: "none", typ: "JWT" }));
	let payload = crypto.b64url_encode(sprintf("%J", { sub: "admin" }));
	let token = none_header + "." + payload + ".";

	// 1. JWT High-level
	let res = crypto.verify_jwt(token, "secret", { alg: "RS256", now: 123, clock_tolerance: 300 });
	assert_eq(res.error, "ALGORITHM_MISMATCH");

	// 2. JWS Primitive
	res = crypto.verify_jws(token, "secret");
	assert_eq(res.error, "UNSUPPORTED_ALGORITHM");
});

test('Security: JWT - Reject Stripped Signature', () => {
    let header = crypto.b64url_encode(sprintf("%J", { alg: "HS256" }));
    let payload = crypto.b64url_encode(sprintf("%J", { sub: "admin" }));
    let stripped = header + "." + payload + ".";
    
    let res = crypto.verify_jwt(stripped, "secret", { alg: "HS256", now: 123, clock_tolerance: 300 });
    assert_eq(res.error, "INVALID_SIGNATURE_ENCODING");
});

test('Security: JWT - Payload Integrity', () => {
	let secret = "secret";
	let good_token = crypto.sign_jws({foo: "bar"}, secret);
	let parts = split(good_token, ".");
    
    // Tamper with payload (malformed JSON)
	let bad_payload = crypto.b64url_encode("{ invalid json }");
	let tampered = parts[0] + "." + bad_payload + "." + parts[2];
	
		let res = crypto.verify_jws(tampered, secret);
	
		assert_eq(res.error, "INVALID_SIGNATURE", "Tampering must invalidate HMAC signature");
	
	});
	
	
	
	test('Security: PII - Ensure logs never contain raw identifiers (Email/@)', () => {
	
		let factory = mock.create();
	
		let user_data = {
	
			sub: "123456789",
	
			email: "attacker@evil.com",
	
			name: "Evil Attacker"
	
		};
	
	
	
		// 1. Session Creation Flow
	
		let data = factory.with_env({}, (io) => {
	
			// Mock secret key exists
	
			io.write_file("/etc/luci-sso/secret.key", "01234567890123456789012345678901");
	
			
	
			return factory.using(io).spy((spying_io) => {
	
				session.create(spying_io, user_data);
	
			});
	
		});
	
	
	
		// ASSERTION: Verify that no log message contains the '@' symbol or the raw name
	
		for (let call in data.calls) {
	
			if (call[0] == "log") {
	
				let msg = call[2];
	
				assert(!match(msg, /@/), `Security Violation: Raw email found in logs: ${msg}`);
	
				assert(!match(msg, /Evil Attacker/), `Security Violation: Raw name found in logs: ${msg}`);
	
			}
	
		}
	
	});
	
	