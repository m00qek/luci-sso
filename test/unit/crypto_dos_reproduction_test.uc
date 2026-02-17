import { test, assert, assert_eq } from '../testing.uc';
import * as crypto from 'luci_sso.crypto';

test('crypto: security - W1: constant_time_eq length cap', () => {
	let secret = "short_secret";
	
	// Create a string longer than 16KB (e.g. 32KB) to trigger the cap
	let long_str = "A";
	for (let i = 0; i < 15; i++) {
		long_str += long_str; // 2^15 = 32,768 bytes (32KB)
	}

	let res = crypto.constant_time_eq(long_str, secret);
	assert(!res, "Should return false for over-large input (> 16KB)");
});
