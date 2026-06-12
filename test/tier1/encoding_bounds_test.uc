import { describe, it, assert } from 'utest';
import * as encoding from 'luci_sso.encoding';

describe('encoding: binary_truncate', () => {
	it('enforces bounds check', () => {
		let data = "short";
		assert.throws(() => encoding.binary_truncate(data, 10), /CONTRACT_VIOLATION/, "Should contain CONTRACT_VIOLATION in error");
		assert.throws(() => encoding.binary_truncate(data, 10), /truncation length exceeds data length/, "Should contain reason in error");
	});
});
