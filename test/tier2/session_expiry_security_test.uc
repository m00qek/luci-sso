import { describe, it, assert, falsy } from 'utest';
import { with_context } from 'context';
import * as session from 'luci_sso.session';

const FIXED_NOW = 1516239022;

describe('session: verify_state', () => {
	it('rejects handshake with exp=0 as expired', () => {
		with_context({
			fs:    {},
			clock: { data: { now: FIXED_NOW } }
		}, (deps) => {
			let s_res = session.create_state(deps);
			let handle = s_res.data.token;
			let path = `/var/run/luci-sso/handshake_${handle}.json`;

			let data = json(deps.fs.readfile(path));
			data.exp = 0;
			deps.fs.writefile(path, sprintf("%J", data));

			let res = session.verify_state(deps, handle, 300);
			assert.match(falsy(), res.ok, "Should fail verification");
			assert.match("HANDSHAKE_EXPIRED", res.error, "Should be rejected as expired even if exp is 0 (truthy guard fix)");
		});
	});

	it('rejects handshake with missing exp as corrupted', () => {
		with_context({
			fs:    {},
			clock: { data: { now: FIXED_NOW } }
		}, (deps) => {
			let s_res = session.create_state(deps);
			let handle = s_res.data.token;
			let path = `/var/run/luci-sso/handshake_${handle}.json`;

			let data = json(deps.fs.readfile(path));
			delete data.exp;
			deps.fs.writefile(path, sprintf("%J", data));

			let res = session.verify_state(deps, handle, 300);
			assert.match(falsy(), res.ok, "Should fail verification");
			assert.match("STATE_CORRUPTED", res.error, "Should be rejected as corrupted if exp is missing");
		});
	});

	it('rejects handshake with missing iat as corrupted', () => {
		with_context({
			fs:    {},
			clock: { data: { now: FIXED_NOW } }
		}, (deps) => {
			let s_res = session.create_state(deps);
			let handle = s_res.data.token;
			let path = `/var/run/luci-sso/handshake_${handle}.json`;

			let data = json(deps.fs.readfile(path));
			delete data.iat;
			deps.fs.writefile(path, sprintf("%J", data));

			let res = session.verify_state(deps, handle, 300);
			assert.match(falsy(), res.ok, "Should fail verification");
			assert.match("STATE_CORRUPTED", res.error, "Should be rejected as corrupted if iat is missing");
		});
	});
});
