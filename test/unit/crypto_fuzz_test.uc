import { test, assert, assert_eq, assert_throws } from 'testing';
import * as crypto from 'luci_sso.crypto';
import * as fixtures from 'fixtures';

test('Fuzz: Base64URL Roundtrip', () => {
	let cases = [
		"",
		"f",
		"fo",
		"foo",
		"foob",
		"fooba",
		"foobar",
		"Hello World!",
		"\0\x01\x02\x03",
		"~`1234567890-=[]\\;',./!@#$%^&*()_+{}|:\"<>?",
		"The quick brown fox jumps over the lazy dog"
	];

	for (let i, original in cases) {
		let encoded = crypto.b64url_encode(original);
		assert(!match(encoded, /[+/=]/), `Encoded string '${encoded}' should not contain +, / or =`);
		let decoded = crypto.b64url_decode(encoded);
		assert_eq(original, decoded, `Roundtrip failed for case: ${original}`);
	}
});

test('Fuzz: Base64URL Edge Cases', () => {
	// Invalid characters
	assert_eq(crypto.b64url_decode("YQ+B"), null, "Should reject standard B64 '+'");
	assert_eq(crypto.b64url_decode("YQ/B"), null, "Should reject standard B64 '/' ");
	assert_eq(crypto.b64url_decode("YQ== "), null, "Should reject padding '=' ");
	assert_eq(crypto.b64url_decode("YQ@B"), null, "Should reject invalid chars '@'");
	
	// Non-string inputs (should throw CONTRACT_VIOLATION)
	assert_throws(() => crypto.b64url_decode(null));
	assert_throws(() => crypto.b64url_decode(123));
	assert_throws(() => crypto.b64url_decode({}));
});

test('Fuzz: Large Input', () => {
	let large = "";
	for (let i = 0; i < 1000; i++) {
		large += "LargeDataPayload";
	}
	let encoded = crypto.b64url_encode(large);
	let decoded = crypto.b64url_decode(encoded);
	assert_eq(large, decoded, "Should handle large payloads");
});

test('Fuzz: Malformed structures', () => {
	let secret = "secret";
	let cases = [
		"",
		".",
		"..",
		"...",
		"a.b.c.d",
		"eyalg:none.payload.sig",
		" . . "
	];

	for (let i, token in cases) {
		// Should return error object, not crash
		let res1 = crypto.verify_jws(token, secret);
		assert(!res1.ok && res1.error, `JWS verify should fail for: ${token}`);

		let res2 = crypto.verify_jwt(token, "pubkey", { alg: "RS256" });
		assert(!res2.ok && res2.error, `JWT verify should fail for: ${token}`);
	}
});

test('Fuzz: JSON Deep Nesting (JSON Bomb)', () => {
	let depth = 20;
	let bomb = { a: 1 };
	for (let i = 0; i < depth; i++) {
		bomb = { inner: bomb };
	}

	let secret = "secret";
	let token = crypto.sign_jws(bomb, secret);
	assert(token, "Should sign deeply nested object");

	let result = crypto.verify_jws(token, secret);
	assert(result.ok, "Should verify deeply nested object");
	
	// Verify we can reach the bottom
	let current = result.data;
	for (let i = 0; i < depth; i++) {
		current = current.inner;
	}
	assert_eq(current.a, 1);
});

test('Fuzz: Binary Garbage', () => {
	let secret = "secret";
	// Pass 1KB of random binary data as a token
	let garbage = crypto.random(1024);
	
	let res1 = crypto.verify_jws(garbage, secret);
	assert(!res1.ok);

	let res2 = crypto.verify_jwt(garbage, "key", { alg: "RS256" });
	assert(!res2.ok);
});

test('Fuzz: Bit Flipping in Signatures', () => {
	let secret = "secret";
	let token = crypto.sign_jws({foo: "bar"}, secret);
	let parts = split(token, ".");
	let sig = crypto.b64url_decode(parts[2]);
	
	// Flip bits in the middle of the signature
	let sig_arr = [];
	for (let i = 0; i < length(sig); i++) push(sig_arr, ord(sig, i));
	
	sig_arr[10] ^= 0xFF;
	
	let tampered_sig = "";
	for (let i, b in sig_arr) tampered_sig += chr(b);
	
	let tampered_token = parts[0] + "." + parts[1] + "." + crypto.b64url_encode(tampered_sig);
	
	let result = crypto.verify_jws(tampered_token, secret);
	assert_eq(result.error, "INVALID_SIGNATURE");
});

test('Fuzz: JWS Header Injection', () => {
	let secret = "secret";
	let payload = { foo: "bar" };
	let header = { alg: "HS256", typ: "JWT", critical: ["exp"], exp: 123456 }; // Adding non-standard fields
	
	let b64_header = crypto.b64url_encode(sprintf("%J", header));
	let b64_payload = crypto.b64url_encode(sprintf("%J", payload));
	let signed_data = b64_header + "." + b64_payload;
	
	// Use require to get native if needed, but sign_jws should be used if possible
	// Actually we want to test that verify_jws accepts the token
	let import_native = require('luci_sso.native');
	let signature = import_native.hmac_sha256(secret, signed_data);
	let token = signed_data + "." + crypto.b64url_encode(signature);

	// Library should verify successfully but ignore the extra header fields
	let result = crypto.verify_jws(token, secret);
	assert(result.ok, `Should ignore extra header fields, got: ${result.error}`);
	assert_eq(result.data.foo, "bar");
});

test('Fuzz: Token Size Limit (16 KB)', () => {
	let secret = "secret";
	// Create a token slightly larger than 16 KB
	let massive = "";
	for (let i = 0; i < 1640; i++) massive += "1234567890";
	
	let result = crypto.verify_jws(massive, secret);
	assert_eq(result.error, "TOKEN_TOO_LARGE");

	let result_jwt = crypto.verify_jwt(massive, "key", { alg: "RS256" });
	assert_eq(result_jwt.error, "TOKEN_TOO_LARGE");
});