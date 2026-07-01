import { describe, it, assert, falsy, mock, spy } from 'utest';
import * as session from 'luci_sso.session';

describe('session: get_secret_key', () => {
	it('handle write failure', () => {
		mock.inject('fs', {
			behavior: { readfile: () => null, writefile: () => null }
		}, (fs) => {
			let deps = { fs, log: () => null, clock: { time: () => 1516239022, sleep: () => null } };
			let res = session.get_secret_key(deps);

			assert.match(falsy(), res.ok, "get_secret_key should fail when write_file fails");
			assert.match("SYSTEM_KEY_WRITE_FAILED", res.error);

			let unlink_calls = spy(fs).calls.unlink || [];
			let lock_removed = false;
			for (let call in unlink_calls) {
				if (call[0] === "/etc/luci-sso/secret.key.lock") lock_removed = true;
			}
			assert.match(true, lock_removed, "Lock directory should be removed after failure");
		});
	});
});
