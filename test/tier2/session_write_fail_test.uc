import { it, assert, falsy, mock } from 'utest';
import * as session from 'luci_sso.session';

it('session: get_secret_key - handle write failure', () => {
	mock.inject('fs', {
		behavior: { writefile: () => null }
	}, (fs) => {
		let deps = { fs, log: () => null, clock: { time: () => 1516239022, sleep: () => null } };
		let res = session.get_secret_key(deps);

		assert.match(falsy(), res.ok, "get_secret_key should fail when write_file fails");
		assert.match("SYSTEM_KEY_WRITE_FAILED", res.error);

		// Ensure lock is removed even on failure
		let unlink_calls = fs.__utest__.calls.unlink || [];
		let lock_removed = false;
		for (let call in unlink_calls) {
			if (call[0] === "/etc/luci-sso/secret.key.lock") lock_removed = true;
		}
		assert.match(true, lock_removed, "Lock directory should be removed after failure");
	});
});
