import { describe, it, assert, truthy } from 'utest';
import * as session from 'luci_sso.session';
import { with_context } from 'context';

describe('handshake: security', () => {
	it('enforce hard capacity limit (DoS Protection)', () => {
		let mtime = 1000;

		with_context({
			fs: {
				data: {},
				behavior: {
					stat: (path) => ({ mtime: mtime++ })
				}
			},
			clock: { data: { now: 0 } }
		}, (deps) => {
			for (let i = 0; i < 100; i++) {
				let res = session.create_state(deps);
				assert.match(truthy(), res.ok, `Failed to create handshake #${i}: ${res.error}`);
			}

			let files = deps.fs.lsdir("/var/run/luci-sso");
			let files_before = 0;
			for (let f in files) if (match(f, /^handshake_.*\.json$/)) files_before++;

			assert.match(100, files_before, "Should have exactly 100 handshake files");

			let res_101 = session.create_state(deps);
			assert.match(truthy(), res_101.ok, "101st handshake should succeed after emergency reap");

			files = deps.fs.lsdir("/var/run/luci-sso");
			let files_after = 0;
			for (let f in files) if (match(f, /^handshake_.*\.json$/)) files_after++;

			// Expected: 100 (original) - 50 (reaped) + 1 (new) = 51
			assert.match(51, files_after, "Emergency reap should have cleared 50% of oldest handshakes");
		});
	});
});
