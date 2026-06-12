import { describe, it, assert, truthy, falsy } from 'utest';
import * as crypto from 'luci_sso.crypto';

describe('crypto: security', () => {
	it('W1: constant_time_eq length cap', () => {
		let secret = "short_secret";

		let long_str = "A";
		for (let i = 0; i < 15; i++) {
			long_str += long_str; // 2^15 = 32,768 bytes (32KB)
		}

		let res = crypto.constant_time_eq(long_str, secret);
		assert.match(falsy(), res, "Should return false for over-large input (> 16KB)");
	});
});
