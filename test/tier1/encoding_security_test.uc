import { safe_json, normalize_sub } from 'luci_sso.encoding';
import { assert, assert_eq, test } from 'testing';

test('encoding: security - safe_json does not leak raw fragments on failure', () => {
    let sensitive_data = '{"token": "SECRET_1234567890", "garbage": '; // Malformed JSON
    let res = safe_json(sensitive_data);
    
    assert(!res.ok, "Should fail to parse malformed JSON");
    assert(res.raw_fragment === undefined, "Error response MUST NOT contain raw_fragment (W4)");
});

test('encoding: security - safe_json handles binary input safely', () => {
    let binary_data = '\x00\xFF\xDEAD\xBEEF';
    let res = safe_json(binary_data);
    
    assert(!res.ok, "Binary data is not valid JSON");
    assert(res.raw_fragment === undefined, "Should not leak binary fragments");
});

test('encoding: security - normalize_sub enforces lowercase', () => {
	assert_eq(normalize_sub("USER-123").data, "user-123", "Should lowercase sub claim");
	assert_eq(normalize_sub("MixedCase-User").data, "mixedcase-user", "Should lowercase sub claim");
	assert_eq(normalize_sub("already-lower").data, "already-lower", "Should handle already lowercase sub");
});

test('encoding: security - normalize_sub contract violation', () => {
	try {
		normalize_sub(null);
		assert(false, "Should have thrown for null sub");
	} catch (e) {
		assert(index(e, "CONTRACT_VIOLATION") >= 0);
	}
});
