import { test, assert, assert_eq } from '../testing.uc';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

test('session: race condition - should fail instead of falling back to random key when lock is held', () => {
	const lock_path = "/etc/luci-sso/secret.key.lock";
	mock.create()
		.with_files({
			// Path exists but is empty (simulating partial write or race)
			"/etc/luci-sso/secret.key": "",
			// PRE-EXISTING LOCK DIRECTORY (mkdir will return false)
			[lock_path]: { ".type": "directory" }
		})
		.with_env({}, (io) => {
			let res = session.get_secret_key(io);
			
			assert(!res.ok, "Should NOT return ok if key is missing and lock is held");
			assert_eq(res.error, "SYSTEM_KEY_UNAVAILABLE");
		});
});

test('security: secret key bootstrap retries and succeeds if file appears (B2)', () => {
	let read_attempts = 0;
	const mock_factory = mock.create().with_files({
		"/etc/luci-sso/secret.key.lock": { ".type": "directory" }
	});

	mock_factory.with_env({}, (io) => {
		// Override read_file to simulate file appearing after 2 retries
		let original_read = io.read_file;
		io.read_file = (path) => {
			if (path === "/etc/luci-sso/secret.key") {
				read_attempts++;
				if (read_attempts > 2) return "recovered-key-12345678901234567890";
			}
			return original_read(path);
		};

		let res = session.get_secret_key(io);
		assert(res.ok, "Should eventually succeed after retries");
		assert_eq(res.data, "recovered-key-12345678901234567890");
		assert(read_attempts > 1, "Should have performed retries");
	});
});

test('security: secret key bootstrap fails after maximum retries (B2)', () => {
	let read_attempts = 0;
	const mock_factory = mock.create().with_files({
		"/etc/luci-sso/secret.key.lock": { ".type": "directory" }
	});

	mock_factory.with_env({}, (io) => {
		let original_read = io.read_file;
		io.read_file = (path) => {
			if (path === "/etc/luci-sso/secret.key") {
				read_attempts++;
			}
			return original_read(path);
		};

		let res = session.get_secret_key(io);
		assert(!res.ok, "Should fail after max retries");
		assert_eq(res.error, "SYSTEM_KEY_UNAVAILABLE");
		assert_eq(read_attempts, 6, "Should have tried 6 times (1 initial + 5 retries)");
	});
});
