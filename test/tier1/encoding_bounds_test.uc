import { test, assert, assert_eq } from 'testing';
import * as encoding from 'luci_sso.encoding';

test('encoding: binary_truncate - enforces bounds check', () => {
	let data = "short";
	
    try {
        encoding.binary_truncate(data, 10);
        assert(false, "Should have thrown for overflow");
    } catch (e) {
        assert(index(e, "CONTRACT_VIOLATION") >= 0, "Should contain CONTRACT_VIOLATION in error");
        assert(index(e, "truncation length exceeds data length") >= 0, "Should contain reason in error");
    }
});
