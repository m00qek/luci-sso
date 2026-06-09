import { it, assert, truthy, falsy, mock } from 'utest';
import * as session from 'luci_sso.session';

const FIXED_NOW = 1516239022;
const LOCK_PATH = "/etc/luci-sso/secret.key.lock";
const KEY_PATH = "/etc/luci-sso/secret.key";

it('session: race condition - should fail instead of falling back to random key when lock is held', () => {
	mock.inject('fs', {
		data: { [KEY_PATH]: "" },
		behavior: {
			mkdir: (path) => {
				if (path === LOCK_PATH) return false;
				return true;
			},
			readfile: () => null
		}
	}, (fs) => {
		let res = session.get_secret_key({ fs, log: () => null, clock: { time: () => FIXED_NOW, sleep: () => null } });
		assert.match(falsy(), res.ok, "Should NOT return ok if key is missing and lock is held");
		assert.match("SYSTEM_KEY_UNAVAILABLE", res.error);
	});
});

it('security: secret key bootstrap retries and succeeds if file appears (B2)', () => {
	let read_attempts = 0;

	mock.inject('fs', {
		behavior: {
			mkdir: (path) => {
				if (path === LOCK_PATH) return false;
				return true;
			},
			readfile: (path) => {
				if (path === KEY_PATH) {
					read_attempts++;
					return (read_attempts > 2) ? "recovered-key-12345678901234567890" : null;
				}
				return null;
			}
		}
	}, (fs) => {
		let res = session.get_secret_key({ fs, log: () => null, clock: { time: () => FIXED_NOW, sleep: () => null } });
		assert.match(truthy(), res.ok, "Should eventually succeed after retries");
		assert.match("recovered-key-12345678901234567890", res.data);
	});

	assert.match(truthy(), read_attempts > 1, "Should have performed retries");
});

it('security: secret key bootstrap fails after maximum retries (B2)', () => {
	let read_attempts = 0;

	mock.inject('fs', {
		behavior: {
			mkdir: (path) => {
				if (path === LOCK_PATH) return false;
				return true;
			},
			readfile: (path) => {
				if (path === KEY_PATH) read_attempts++;
				return null;
			}
		}
	}, (fs) => {
		let res = session.get_secret_key({ fs, log: () => null, clock: { time: () => FIXED_NOW, sleep: () => null } });
		assert.match(falsy(), res.ok, "Should fail after max retries");
		assert.match("SYSTEM_KEY_UNAVAILABLE", res.error);
	});

	assert.match(6, read_attempts, "Should have tried 6 times (1 initial + 5 retries)");
});
