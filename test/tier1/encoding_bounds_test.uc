import { test, assert, assert_match, assert_fail } from 'testing';
import * as encoding from 'luci_sso.encoding';

test('encoding: binary_truncate - enforces bounds check', () => {
	let data = "short";
	
	try {
		encoding.binary_truncate(data, 10);
		assert_fail("Should have died due to contract violation (len > length(data))");
	} catch (e) {
		assert_match(e, /truncation length exceeds data length/, "Error message should mention length overflow");
	}
});
