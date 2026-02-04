import { test, assert, assert_eq } from 'testing';
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
	
	// Non-string inputs
	assert_eq(crypto.b64url_decode(null), null);
	assert_eq(crypto.b64url_decode(123), null);
	assert_eq(crypto.b64url_decode({}), null);
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
		assert(res1.error, `JWS verify should fail for: ${token}`);

		let res2 = crypto.verify_jwt(token, "pubkey", { alg: "RS256" });
		assert(res2.error, `JWT verify should fail for: ${token}`);
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
	assert(!result.error, "Should verify deeply nested object");
	
	// Verify we can reach the bottom
	let current = result.payload;
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
	assert(res1.error);

	let res2 = crypto.verify_jwt(garbage, "key", { alg: "RS256" });
	assert(res2.error);
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