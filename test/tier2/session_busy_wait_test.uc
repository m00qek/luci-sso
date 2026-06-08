import { it, assert, truthy } from 'utest';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

it('session: security - get_secret_key avoids infinite busy-wait', () => {
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
			assert.match(1, s, "Should sleep for exactly 1 second");
			sleep_calls++;
		};

		let res = session.get_secret_key(io);
		
		assert.match(truthy(), !res.ok);
		assert.match("SYSTEM_KEY_UNAVAILABLE", res.error);
		
		// Each retry (max 5) should perform exactly one sleep(1).
		assert.match(5, sleep_calls, "Should have slept exactly once per retry attempt");
	});
});
