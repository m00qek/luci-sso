import { describe, it, assert, contains } from 'utest';
import { create } from 'luci_sso.deps';
import * as ubus_mod from 'luci_sso.ubus';
import * as r from 'lib.rpcd';

// System bucket: SSO sessions in the container's REAL rpcd, across reloads.
//
// rpcd does not keep the rights it stored in a session when it reloads
// (SIGHUP): it rebuilds them from the login entry whose username matches the
// session's. An SSO session is named sso:<role>, the username of the role's
// entry luci_sso_<role>, so a reload must give it back exactly the rights it
// had, and a session whose entry is missing must get nothing, not the rights
// of a similarly named login such as root.

const ROLE = "systest_reload";

// Makes rpcd reload the way a package install or the luci-sso object does.
function reload(conn) {
	r.await_reload(conn, () => system("kill -HUP $(pidof rpcd)"));
}

// deps with every ubus call recorded as "object.method".
function recording_deps(calls) {
	let deps = create();
	let real = deps.ubus;
	deps.ubus = { call: (o, m, a) => { push(calls, `${o}.${m}`); return real.call(o, m, a); } };
	return deps;
}

// Runs fn(conn) with the role's entry absent before and after.
function with_rpcd(fn) {
	let conn = r.connect(), failure = null;
	r.drop_section(r.ENTRY_PREFIX + ROLE);
	try { fn(conn); } catch (e) { failure = e; }
	try { r.drop_section(r.ENTRY_PREFIX + ROLE); } catch (e) { if (failure == null) failure = e; }
	if (failure != null) die(failure);
}

describe('system: SSO sessions across an rpcd reload', () => {
	let survives = (label, lists) => it(label, () => {
		with_rpcd((conn) => {
			r.put_login(r.ENTRY_PREFIX + ROLE, { username: `sso:${ROLE}`, ...lists });
			let res = ubus_mod.create_passwordless_session(create(), ROLE, "reload@test", "at", "rt", "it");
			assert.match(true, res.ok, `SSO session: ${res.error}`);
			let sid = res.data;
			try {
				let before = r.acls_of(conn, sid);
				assert.match(true, length(keys(before)) > 0, "the session has rights before the reload");

				reload(conn);

				let after = r.acls_of(conn, sid);
				assert.match(sort(keys(before)), sort(keys(after)), "the reload rebuilds exactly the same rights");
				assert.match(contains({ username: `sso:${ROLE}`, oidc_user: "reload@test" }),
					conn.call("session", "get", { ubus_rpc_session: sid }).values, "and keeps the session's values");
			} catch (e) {
				conn.call("session", "destroy", { ubus_rpc_session: sid });
				die(e);
			}
			conn.call("session", "destroy", { ubus_rpc_session: sid });
		});
	});

	survives("a restricted role keeps its rights", {
		read: [ "luci-base", "luci-mod-status-*" ], write: [ "luci-mod-system-config" ]
	});
	survives("a restricted role as the luci-sso object stores it keeps its rights, unauthenticated included", {
		read: [ "luci-mod-status-*", "unauthenticated" ], write: []
	});
	survives("a full admin role keeps its rights", { read: [ "*" ], write: [ "*" ] });
	survives("a role that grants only unauthenticated keeps it", { read: [ "unauthenticated" ], write: [] });

	it("a session named sso:root gets no rights when there is no such entry, although a root login exists", () => {
		with_rpcd((conn) => {
			let root = filter(r.rpcd_sections(), (s) => s[".type"] == "login" && s.username == "root");
			assert.match(1, length(root), "the stock root login is there");
			assert.match(0, length(filter(r.rpcd_sections(), (s) => s.username == "sso:root")), "no sso:root entry");

			let sid = r.marked_session(conn, "sso:root");
			try {
				reload(conn);
				assert.match({}, r.acls_of(conn, sid), "rpcd rebuilt the session with no rights at all");
			} catch (e) {
				conn.call("session", "destroy", { ubus_rpc_session: sid });
				die(e);
			}
			conn.call("session", "destroy", { ubus_rpc_session: sid });
		});
	});
});

describe('system: luci-sso refuses to create a session', () => {
	it("for a role named root, whose entry is missing, instead of using the root login", () => {
		with_rpcd((conn) => {
			let calls = [];
			let res = ubus_mod.create_passwordless_session(recording_deps(calls), "root", "x@test", "at", "rt", "it");
			assert.match(contains({ ok: false, error: "MISSING_RPCD_LOGIN" }), res);
			assert.match([], calls, "no session was created");
		});
	});

	// libuci drops an option with an empty value when it parses a file, so an
	// empty password cannot reach rpcd or luci-sso through UCI; the unit tests
	// cover it.
	it("for a role whose entry has a password option", () => {
		with_rpcd((conn) => {
			for (let pw in [ "$p$root", "x" ]) {
				r.put_login(r.ENTRY_PREFIX + ROLE, { username: `sso:${ROLE}`, password: pw, read: [ "*" ] });
				let calls = [];
				let res = ubus_mod.create_passwordless_session(recording_deps(calls), ROLE, "x@test", "at", "rt", "it");
				assert.match(contains({ ok: false, error: "INSECURE_RPCD_LOGIN" }), res);
				assert.match([], calls, "no session was created");
			}
		});
	});
});
