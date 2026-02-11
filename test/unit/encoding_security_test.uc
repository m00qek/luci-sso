import { safe_json } from 'luci_sso.crypto';
import { assert, test } from '../testing.uc';

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
