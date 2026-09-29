'use strict';
import { describe, it, assert } from 'utest';

// Integration bucket — enter where LuCI's dispatcher enters: the admin/logout
// menu override calls luci.controller.sso's action_logout with ctx, http and
// ubus as globals (call(fn, mod, runtime.env)). The controller ships in
// files/usr/share/ucode/luci/controller/ and the devenv mounts it there.
//
// The LuCI branch delegates to require('luci.controller.admin.index'). The
// dispatcher's scope reaches that nested call, and so does ours: a `modules`
// entry in the scope stands in for LuCI's module, so the test observes the
// delegation without loading LuCI's whole controller.

const CONTROLLER = '/usr/share/ucode/luci/controller/sso.uc';

function run(opts) {
	let calls = [];
	let ctl = loadfile(CONTROLLER)();
	let env = proto({
		ctx: { authsession: opts.sid, authtoken: opts.token },
		ubus: {
			call: (obj, method, args) => {
				push(calls, [ 'ubus', obj, method, args?.ubus_rpc_session ]);
				return (opts.values == null) ? null : { values: opts.values };
			}
		},
		http: { redirect: (url) => push(calls, [ 'redirect', url ]) },
		modules: {
			'luci.controller.admin.index': {
				action_logout: function() { push(calls, [ 'luci-logout', ctx.authsession ]); }
			}
		}
	}, global);
	let err = null;
	try { call(ctl.action_logout, ctl, env); } catch (e) { err = `${e}`; }
	return { calls, err };
}

describe('luci.controller.sso: action_logout', () => {
	it('sends an SSO session to luci-sso /logout with the session CSRF token', () => {
		let r = run({ sid: 'S1', token: 'tok/+=', values: { username: 'sso:admin', oidc_user: 'a@example.com', token: 'tok/+=' } });
		assert.match(null, r.err);
		assert.match([
			[ 'ubus', 'session', 'get', 'S1' ],
			[ 'redirect', '/cgi-bin/luci-sso/logout?stoken=tok%2F%2B%3D' ],
		], r.calls);
	});

	it('sends an SSO session without an email to luci-sso /logout too', () => {
		// A user matched by group whose IdP sends no email: no oidc_user value.
		let r = run({ sid: 'S5', token: 't', values: { username: 'sso:viewer', token: 't' } });
		assert.match(null, r.err);
		assert.match([
			[ 'ubus', 'session', 'get', 'S5' ],
			[ 'redirect', '/cgi-bin/luci-sso/logout?stoken=t' ],
		], r.calls);
	});

	it('gives a session whose username is not sso:<role> LuCI\'s own logout, even with an oidc_user value', () => {
		let r = run({ sid: 'S6', token: 't', values: { username: 'root', oidc_user: 'a@example.com', token: 't' } });
		assert.match([
			[ 'ubus', 'session', 'get', 'S6' ],
			[ 'luci-logout', 'S6' ],
		], r.calls);
	});

	it('gives a password session LuCI\'s own logout', () => {
		let r = run({ sid: 'S2', token: 't', values: { username: 'root', token: 't' } });
		assert.match([
			[ 'ubus', 'session', 'get', 'S2' ],
			[ 'luci-logout', 'S2' ],
		], r.calls);
	});

	it('falls back to LuCI\'s logout when the session cannot be looked up', () => {
		let r = run({ sid: 'S3', token: 't', values: null });
		assert.match([ 'luci-logout', 'S3' ], r.calls[length(r.calls) - 1]);
		assert.match(0, length(filter(r.calls, (c) => c[0] == 'redirect')));
	});

	it('falls back to LuCI\'s logout without a CSRF token, without asking rpcd', () => {
		let r = run({ sid: 'S4', token: null, values: { username: 'sso:admin', oidc_user: 'a@example.com' } });
		assert.match([ [ 'luci-logout', 'S4' ] ], r.calls);
	});

	it('falls back to LuCI\'s logout when there is no session', () => {
		let r = run({ sid: null, token: null, values: null });
		assert.match([ [ 'luci-logout', null ] ], r.calls);
	});
});
