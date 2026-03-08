import { test, assert, assert_eq } from 'testing';
import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';

// =============================================================================
// Tier 2: Fuzz & Robustness Logic
// =============================================================================

test('fuzz: logic - Base64URL consistency', () => {
	let cases = [
		"",
		"foobar",
		"Hello World!",
		"\0\x01\x02\x03",
		'~`1234567890-=[]\\;\',./!@#$%^&*()_+{}|:"<>?',
		"The quick brown fox jumps over the lazy dog"
	];

	for (let i, original in cases) {
		let encoded_res = encoding.b64url_encode(original);
		assert(encoded_res.ok);
		let encoded = encoded_res.data;
		assert(!match(encoded, /[+/=]/), `Encoded string '${encoded}' should not contain +, / or =`);
		let decoded_res = encoding.b64url_decode(encoded);
		assert(decoded_res.ok);
		let decoded = decoded_res.data;
		assert_eq(original, decoded, `Roundtrip failed for case: ${original}`);
	}
});

test('fuzz: logic - large input stability', () => {
    // 16KB limit check
	let large = "";
	for (let i = 0; i < 1024; i++) {
		large += "1234567890123456";
	}
	let encoded = encoding.b64url_encode(large).data;
	let decoded = encoding.b64url_decode(encoded).data;
	assert_eq(length(decoded), 16384, "Should successfully roundtrip 16KB");
});

test('fuzz: logic - bit flipping resistance', () => {
	let secret = "secret";
	let res_s = crypto.jws_sign({foo: "bar"}, secret);
    assert(Result.is(res_s));
	assert(res_s.ok);
	let token = res_s.data;
	let parts = split(token, ".");
	let sig = encoding.b64url_decode(parts[2]).data;

	// Flip bits in the middle of the signature
    let sig_bytes = [];
    for(let i=0; i<length(sig); i++) push(sig_bytes, ord(sig, i));
    sig_bytes[10] ^= 0xFF;

    let tampered_sig = "";
    for(let i, b in sig_bytes) tampered_sig += chr(b);

	let tampered_token = parts[0] + "." + parts[1] + "." + encoding.b64url_encode(tampered_sig).data;

	let result = crypto.jws_verify(tampered_token, secret);
    assert(Result.is(result));
	assert_eq(result.error, "INVALID_SIGNATURE", "Bit flipping must invalidate signature");
});

test('fuzz: logic - header injection resistance', () => {
	let secret = "secret";
	let payload = { foo: "bar" };
	let header = { alg: "HS256", typ: "JWT", malicious_extra: "ignore-me" }; 

	let b64_header = encoding.b64url_encode(sprintf("%J", header)).data;
	let b64_payload = encoding.b64url_encode(sprintf("%J", payload)).data;
	let signed_data = b64_header + "." + b64_payload;

    // We use raw native to create a signature with an "illegal" header
	let import_native = require('luci_sso.native');
	let signature = import_native.hmac_sha256(secret, signed_data);
	let token = signed_data + "." + encoding.b64url_encode(signature).data;

	let result = crypto.jws_verify(token, secret);
    assert(Result.is(result));
	assert(result.ok, "Should verify despite extra header fields (Forward Compatibility)");
	assert_eq(result.data.foo, "bar");
});
