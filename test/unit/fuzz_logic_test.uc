import { test, assert, assert_eq } from 'testing';
import * as crypto from 'luci_sso.crypto';

// =============================================================================
// Tier 2: Fuzz & Robustness Logic
// =============================================================================

test('LOGIC: Fuzz - Base64URL Consistency', () => {
	let cases = [
		"",
		"foobar",
		"Hello World!",
		"\0\x01\x02\x03",
		'~`1234567890-=[]\\;\',./!@#$%^&*()_+{}|:"<>?',
		"The quick brown fox jumps over the lazy dog"
	];

	for (let i, original in cases) {
		let encoded = crypto.b64url_encode(original);
		assert(!match(encoded, /[+/=]/), `Encoded string '${encoded}' should not contain +, / or =`);
		let decoded = crypto.b64url_decode(encoded);
		assert_eq(original, decoded, `Roundtrip failed for case: ${original}`);
	}
});

test('LOGIC: Fuzz - Large Input Stability', () => {
    // 16KB limit check
	let large = "";
	for (let i = 0; i < 1024; i++) {
		large += "1234567890123456";
	}
	let encoded = crypto.b64url_encode(large);
	let decoded = crypto.b64url_decode(encoded);
	assert_eq(length(decoded), 16384, "Should successfully roundtrip 16KB");
});

test('LOGIC: Fuzz - Bit Flipping Resistance', () => {
	let secret = "secret";
	let token = crypto.sign_jws({foo: "bar"}, secret);
	let parts = split(token, ".");
	let sig = crypto.b64url_decode(parts[2]);
	
	// Flip bits in the middle of the signature
    let sig_bytes = [];
    for(let i=0; i<length(sig); i++) push(sig_bytes, ord(sig, i));
    sig_bytes[10] ^= 0xFF;
    
    let tampered_sig = "";
    for(let i, b in sig_bytes) tampered_sig += chr(b);
	
	let tampered_token = parts[0] + "." + parts[1] + "." + crypto.b64url_encode(tampered_sig);
	
	let result = crypto.verify_jws(tampered_token, secret);
	assert_eq(result.error, "INVALID_SIGNATURE", "Bit flipping must invalidate signature");
});

test('LOGIC: Fuzz - Header Injection Resistance', () => {
	let secret = "secret";
	let payload = { foo: "bar" };
	let header = { alg: "HS256", typ: "JWT", malicious_extra: "ignore-me" }; 
	
	let b64_header = crypto.b64url_encode(sprintf("%J", header));
	let b64_payload = crypto.b64url_encode(sprintf("%J", payload));
	let signed_data = b64_header + "." + b64_payload;
	
    // We use raw native to create a signature with an "illegal" header
	let import_native = require('luci_sso.native');
	let signature = import_native.hmac_sha256(secret, signed_data);
	let token = signed_data + "." + crypto.b64url_encode(signature);

	let result = crypto.verify_jws(token, secret);
	assert(result.ok, "Should verify despite extra header fields (Forward Compatibility)");
	assert_eq(result.data.foo, "bar");
});