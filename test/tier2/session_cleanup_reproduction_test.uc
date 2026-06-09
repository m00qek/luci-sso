import { it, assert, falsy, mock } from 'utest';
import * as session from 'luci_sso.session';

it('session: reproduction - verify_state cleanup failure on read error (W5)', () => {
	let handle = "repro-W5";
	let path = `/var/run/luci-sso/handshake_${handle}.json`;
	let consume_path = `${path}.consumed`;

	mock.inject('fs', {
		data: { [path]: "{}" },
		behavior: { readfile: () => null }
	}, (fs) => {
		let deps = { fs, log: () => null, clock: { time: () => 1516239022, sleep: () => null } };
		let res = session.verify_state(deps, handle, 300);

		assert.match(falsy(), res.ok, "Should fail due to read error");

		// CRITICAL: Must remove .consumed file even if read fails
		let unlink_calls = fs.__utest__.calls.unlink || [];
		let consume_removed = false;
		for (let call in unlink_calls) {
			if (call[0] === consume_path) consume_removed = true;
		}
		assert.match(true, consume_removed, "CRITICAL: Must remove .consumed file even if read fails");
	});
});
