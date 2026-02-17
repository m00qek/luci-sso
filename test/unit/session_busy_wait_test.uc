import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

test('session: security - get_secret_key avoids infinite busy-wait', () => {
	let factory = mock.create();
	let key_path = "/etc/luci-sso/secret.key";

	factory.with_env({}, (io) => {
		// Mock mkdir to always fail (lock collision)
		io.mkdir = (path) => {
			if (path == key_path + ".lock") return false;
			return true;
		};

		// Mock read_file to always fail (key missing)
		io.read_file = (path) => {
			if (path == key_path) return null;
			return "some content";
		};

		// Monitor sleep() calls to detect correct wait logic
		let sleep_calls = 0;
		io.sleep = (s) => {
			assert_eq(s, 1, "Should sleep for exactly 1 second");
			sleep_calls++;
		};

		let res = session.get_secret_key(io);
		
		assert(!res.ok);
		assert_eq(res.error, "SYSTEM_KEY_UNAVAILABLE");
		
		// Each retry (max 5) should perform exactly one sleep(1).
		assert_eq(sleep_calls, 5, "Should have slept exactly once per retry attempt");
	});
});
