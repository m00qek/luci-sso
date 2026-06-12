import { describe, it, assert, truthy, has_length } from 'utest';
import * as native from 'luci_sso.native';
import * as Result from 'luci_sso.result';

function generate_large(size) {
    let s = "12345678"; // 8 bytes
    while (length(s) * 2 <= size) {
        s += s;
    }
    if (length(s) < size) {
        s += substr(s, 0, size - length(s));
    }
    return s;
}

describe('native: boundary', () => {
	it('sha256 input limits', () => {
		const MAX = 16384;

		let data_ok = generate_large(MAX);
		let res_ok = native.sha256(data_ok);
		assert.match(truthy(), res_ok != null, "Should accept exactly 16384 bytes");
		assert.match(has_length(32), res_ok, "Should return 32-byte hash");

		let data_bad = data_ok + "A";
		let res_bad = native.sha256(data_bad);
		assert.match(null, res_bad, "Should reject 16385 bytes (Null return)");
	});

	it('hmac_sha256 input limits', () => {
		const MAX = 16384;
		let data_ok = generate_large(MAX);
		let key_ok = "secret";

		let res_ok = native.hmac_sha256(key_ok, data_ok);
		assert.match(truthy(), res_ok != null, "Should accept 16384 bytes data");

		let res_key_ok = native.hmac_sha256(data_ok, "msg");
		assert.match(truthy(), res_key_ok != null, "Should accept 16384 bytes key");

		assert.match(null, native.hmac_sha256(key_ok, data_ok + "A"), "Should reject 16385 bytes data");

		assert.match(null, native.hmac_sha256(data_ok + "A", "msg"), "Should reject 16385 bytes key");
	});

	it('verify_rs256 input limits', () => {
		const MAX = 16384;
		let data_ok = generate_large(MAX);
		let sig_ok = generate_large(256); // typical RS256 sig size
		let key_ok = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";

		// We don't need a VALID signature/key here, the boundary check in
		// native_common.c happens BEFORE the crypto library is called.

		assert.match(false, native.verify_rs256(data_ok + "A", sig_ok, key_ok), "Should return false for msg > 16KB");

		assert.match(false, native.verify_rs256(data_ok, data_ok + "A", key_ok), "Should return false for sig > 16KB");

		// Note: native.h has NATIVE_RSA_PEM_MAX (4096), but native_common.c
		// uses NATIVE_MAX_INPUT_SIZE (16384) for the initial boundary check.
		assert.match(false, native.verify_rs256(data_ok, sig_ok, data_ok + "A"), "Should return false for key > 16KB");
	});
});
