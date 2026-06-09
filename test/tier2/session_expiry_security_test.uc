import { it, assert, falsy, mock } from 'utest';
import * as session from 'luci_sso.session';

const FIXED_NOW = 1516239022;

function make_deps(fs) {
	return { fs, log: () => null, clock: { time: () => FIXED_NOW, sleep: () => null } };
}

it('session: verify_state - rejects handshake with exp=0 as expired', () => {
	mock.inject('fs', {}, (fs) => {
		let deps = make_deps(fs);
		let s_res = session.create_state(deps);
		let handle = s_res.data.token;
		let path = `/var/run/luci-sso/handshake_${handle}.json`;

		let data = json(fs.readfile(path));
		data.exp = 0;
		fs.writefile(path, sprintf("%J", data));

		let res = session.verify_state(deps, handle, 300);
		assert.match(falsy(), res.ok, "Should fail verification");
		assert.match("HANDSHAKE_EXPIRED", res.error, "Should be rejected as expired even if exp is 0 (truthy guard fix)");
	});
});

it('session: verify_state - rejects handshake with missing exp as corrupted', () => {
	mock.inject('fs', {}, (fs) => {
		let deps = make_deps(fs);
		let s_res = session.create_state(deps);
		let handle = s_res.data.token;
		let path = `/var/run/luci-sso/handshake_${handle}.json`;

		let data = json(fs.readfile(path));
		delete data.exp;
		fs.writefile(path, sprintf("%J", data));

		let res = session.verify_state(deps, handle, 300);
		assert.match(falsy(), res.ok, "Should fail verification");
		assert.match("STATE_CORRUPTED", res.error, "Should be rejected as corrupted if exp is missing");
	});
});

it('session: verify_state - rejects handshake with missing iat as corrupted', () => {
	mock.inject('fs', {}, (fs) => {
		let deps = make_deps(fs);
		let s_res = session.create_state(deps);
		let handle = s_res.data.token;
		let path = `/var/run/luci-sso/handshake_${handle}.json`;

		let data = json(fs.readfile(path));
		delete data.iat;
		fs.writefile(path, sprintf("%J", data));

		let res = session.verify_state(deps, handle, 300);
		assert.match(falsy(), res.ok, "Should fail verification");
		assert.match("STATE_CORRUPTED", res.error, "Should be rejected as corrupted if iat is missing");
	});
});
