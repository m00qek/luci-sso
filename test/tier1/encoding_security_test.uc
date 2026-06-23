import { safe_json } from 'luci_sso.encoding';
import { describe, it, assert, falsy } from 'utest';

describe('encoding: security', () => {
	it('safe_json does not leak raw fragments on failure', () => {
		let sensitive_data = '{"token": "SECRET_1234567890", "garbage": '; // Malformed JSON
		let res = safe_json(sensitive_data);

		assert.match(falsy(), res.ok, "Should fail to parse malformed JSON");
		assert.match(undefined, res.raw_fragment, "Error response MUST NOT contain raw_fragment (W4)");
	});

	it('safe_json handles binary input safely', () => {
		let binary_data = '\x00\xFF\xDEAD\xBEEF';
		let res = safe_json(binary_data);

		assert.match(falsy(), res.ok, "Binary data is not valid JSON");
		assert.match(undefined, res.raw_fragment, "Should not leak binary fragments");
	});
});
