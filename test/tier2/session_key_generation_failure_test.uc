import { it, assert, truthy, falsy, mock } from 'utest';
import * as session from 'luci_sso.session';

it('session: reproduction - null key propagation on generation failure (B5)', () => {
	mock.inject('fs', {
		behavior: {
			readfile: () => null,
			mkdir:    () => true,
			chmod:    (path, mode) => { die("Permission denied (Mocked)"); }
		}
	}, (fs) => {
		let res = session.get_secret_key({ fs, log: () => null, clock: { time: () => 1516239022, sleep: () => null } });

		if (res.ok && res.data === null) {
			print("FAIL: Reproduced B5 - get_secret_key returned Result.ok(null)\n");
		}

		assert.match(falsy(), res.ok, "Should return error when key generation fails");
		assert.match(
			truthy(),
			res.error === "SYSTEM_KEY_GENERATION_FAILED" || res.error === "SYSTEM_KEY_WRITE_FAILED",
			"Expected key generation or write failure error"
		);
	});
});
