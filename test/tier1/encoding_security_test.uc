import { safe_json, normalize_sub } from 'luci_sso.encoding';
import { it, assert, truthy, falsy } from 'utest';

it('encoding: security - safe_json does not leak raw fragments on failure', () => {
    let sensitive_data = '{"token": "SECRET_1234567890", "garbage": '; // Malformed JSON
    let res = safe_json(sensitive_data);
    
    assert.match(falsy(), res.ok, "Should fail to parse malformed JSON");
    assert.match(undefined, res.raw_fragment, "Error response MUST NOT contain raw_fragment (W4)");
});

it('encoding: security - safe_json handles binary input safely', () => {
    let binary_data = '\x00\xFF\xDEAD\xBEEF';
    let res = safe_json(binary_data);
    
    assert.match(falsy(), res.ok, "Binary data is not valid JSON");
    assert.match(undefined, res.raw_fragment, "Should not leak binary fragments");
});

it('encoding: security - normalize_sub enforces lowercase', () => {
	assert.match("user-123", normalize_sub("USER-123").data, "Should lowercase sub claim");
	assert.match("mixedcase-user", normalize_sub("MixedCase-User").data, "Should lowercase sub claim");
	assert.match("already-lower", normalize_sub("already-lower").data, "Should handle already lowercase sub");
});

it('encoding: security - normalize_sub contract violation', () => {
	try {
		normalize_sub(null);
		assert.match(truthy(), false, "Should have thrown for null sub");
	} catch (e) {
		assert.match(truthy(), index(e, "CONTRACT_VIOLATION") >= 0);
	}
});
