import { it, assert, falsy, mock } from 'utest';
import * as session from 'luci_sso.session';

it('session: security - get_secret_key avoids infinite busy-wait', () => {
	let sleep_calls = 0;
	let clock = {
		time: () => 1516239022,
		sleep: (s) => { assert.match(1, s, "Should sleep for exactly 1 second"); sleep_calls++; }
	};

	mock.inject('fs', {
		behavior: {
			mkdir: (path) => {
				if (path === "/etc/luci-sso/secret.key.lock") return false;
				return true;
			},
			readfile: (path) => {
				if (path === "/etc/luci-sso/secret.key") return null;
				return null;
			}
		}
	}, (fs) => {
		let res = session.get_secret_key({ fs, log: () => null, clock });
		assert.match(falsy(), res.ok);
		assert.match("SYSTEM_KEY_UNAVAILABLE", res.error);
	});

	assert.match(5, sleep_calls, "Should have slept exactly once per retry attempt");
});
