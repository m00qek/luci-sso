import { it, assert, truthy } from 'utest';
import * as encoding from 'luci_sso.encoding';

it('encoding: binary_truncate - enforces bounds check', () => {
	let data = "short";
	
    try {
        encoding.binary_truncate(data, 10);
        assert.match(truthy(), false, "Should have thrown for overflow");
    } catch (e) {
        assert.match(truthy(), index(e, "CONTRACT_VIOLATION") >= 0, "Should contain CONTRACT_VIOLATION in error");
        assert.match(truthy(), index(e, "truncation length exceeds data length") >= 0, "Should contain reason in error");
    }
});
