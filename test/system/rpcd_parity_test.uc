import { describe, it, assert } from 'utest';
import * as ubus_lib from 'ubus';
import * as uci from 'uci';
import { create } from 'luci_sso.deps';
import * as ubus_mod from 'luci_sso.ubus';

// System bucket: runs against the REAL rpcd in the openwrt container, no mocks.
//
// luci-sso expands a role's access groups into concrete ubus/uci/file/cgi-io
// grants itself (ubus.uc, _expand_role), because rpcd does that only for
// password logins. The group DEFINITIONS come from acl.d at every login, but
// the COMBINING RULES (write implies read, table vs array notation, globs,
// negations, which scopes) are a copy of rpcd's C code. This test is the
// guard against that copy drifting: for each role shape it creates an rpcd
// password login with the same lists and an SSO session through the real
// luci-sso path, and requires identical effective ACLs. If a future rpcd
// changes its rules, this fails and prints the entries that differ.

const LOGIN = "ssoparity";

// Two deliberate differences are encoded in the rpcd side of each shape:
// - luci-sso's wildcards only ever match luci-* groups (a hardening), while
//   rpcd's "*" also matches non-luci groups; so '*' becomes "luci-*".
// - every non-admin SSO session also reads the "unauthenticated" group (what
//   rpcd grants an anonymous client, and what LuCI's views need), so the rpcd
//   side lists it explicitly.
const SHAPES = [
	{ name: "read '*' only",               sso: { read: ['*'], write: [] },                                rpcd: { read: ['luci-*', 'unauthenticated'], write: [] } },
	{ name: 'a specific read group',       sso: { read: ['luci-base'], write: [] },                        rpcd: { read: ['luci-base', 'unauthenticated'], write: [] } },
	{ name: 'a specific write group',      sso: { read: [], write: ['luci-mod-system-config'] },           rpcd: { read: ['unauthenticated'], write: ['luci-mod-system-config'] } },
	{ name: "mixed: read '*', write one",  sso: { read: ['*'], write: ['luci-mod-network-config'] },       rpcd: { read: ['luci-*', 'unauthenticated'], write: ['luci-mod-network-config'] } },
	{ name: 'globs and negation',          sso: { read: ['luci-mod-status-*', '!luci-mod-status-logs'], write: [] },
	                                       rpcd: { read: ['luci-mod-status-*', '!luci-mod-status-logs', 'unauthenticated'], write: [] } },
];

function flatten(acls) {
	let out = {};
	for (let scope, objs in (acls || {}))
		for (let obj, fns in objs)
			for (let fn in fns)
				out[`${scope} ${obj} ${fn}`] = true;
	return out;
}

function acls_of(conn, sid) {
	let l = conn.call("session", "list", { ubus_rpc_session: sid });
	return flatten(l ? l.acls : null);
}

function minus(a, b) { return sort(filter(keys(a), (k) => !b[k])); }

// Removes the temporary login by name. Deleting by name (rather than
// restoring a backup of /etc/config/rpcd) also clears an entry left behind by
// a run that was killed before it could clean up.
function drop_login() {
	let cur = uci.cursor();
	if (cur.get("rpcd", LOGIN)) {
		cur.delete("rpcd", LOGIN);
		cur.commit("rpcd");
	}
}

// Runs fn(conn, rpcd_acls, sso_acls) for one shape; always cleans up.
function with_both_sessions(shape, fn) {
	let conn = ubus_lib.connect();
	let rpcd_sid = null, sso_sid = null, failure = null;
	try {
		drop_login();
		let cur = uci.cursor();
		cur.set("rpcd", LOGIN, "login");
		cur.set("rpcd", LOGIN, "username", LOGIN);
		cur.set("rpcd", LOGIN, "password", "$p$root");
		cur.set("rpcd", LOGIN, "read", shape.rpcd.read);
		cur.set("rpcd", LOGIN, "write", shape.rpcd.write);
		cur.commit("rpcd");

		// rpcd re-reads /etc/config/rpcd on each login: no reload needed (and a
		// reload would drop every live session in the container).
		let login = conn.call("session", "login", { username: LOGIN, password: "admin", timeout: 120 });
		assert.match(true, !!login, "rpcd password login for the parity user");
		rpcd_sid = login.ubus_rpc_session;

		let res = ubus_mod.create_passwordless_session(create(), 'root', shape.sso, 'parity@test', 'at', 'rt', 'it');
		assert.match(true, res.ok, `SSO session: ${res.error}`);
		sso_sid = res.data;

		fn(conn, acls_of(conn, rpcd_sid), acls_of(conn, sso_sid));
	} catch (e) {
		failure = e;
	}
	// ucode has no `finally`: clean up, then re-raise any failure.
	if (rpcd_sid) conn.call("session", "destroy", { ubus_rpc_session: rpcd_sid });
	if (sso_sid)  conn.call("session", "destroy", { ubus_rpc_session: sso_sid });
	try { drop_login(); } catch (e) { if (failure == null) failure = e; }
	if (failure != null) die(failure);
}

describe('system: SSO roles match rpcd password logins', () => {
	// A function parameter, not the loop variable: ucode closures created in a
	// `for (let x in ...)` body all see the last element.
	let parity_case = (shape) => it(shape.name, () => {
		with_both_sessions(shape, (conn, rpcd, sso) => {
			let only_rpcd = minus(rpcd, sso), only_sso = minus(sso, rpcd);
			assert.match(true, length(keys(rpcd)) > 0, "the rpcd login received grants");
			assert.match([], only_rpcd, `${shape.name}: granted by rpcd but not by luci-sso: ${join(", ", only_rpcd)}`);
			assert.match([], only_sso,  `${shape.name}: granted by luci-sso but not by rpcd: ${join(", ", only_sso)}`);
		});
	});
	for (let shape in SHAPES) parity_case(shape);

	// Full admin keeps luci-sso's own raw grants (unrestricted ubus/uci/file/
	// cgi-io plus access-group read/write on every luci-* group). It is not an
	// rpcd expansion, so it is compared for coverage, not equality: the SSO
	// admin must be able to do everything an rpcd read '*'/write '*' login can.
	it("write '*' full admin covers everything rpcd grants a '*' login", () => {
		with_both_sessions({ sso: { read: ['*'], write: ['*'] }, rpcd: { read: ['*'], write: ['*'] } }, (conn, rpcd, sso) => {
			let uncovered = filter(minus(rpcd, sso), (k) => {
				let scope = split(k, " ")[0];
				return !sso[`${scope} * *`];
			});
			print(sprintf("\n    [parity] admin: %d rpcd entries, %d SSO entries; not covered by an SSO raw '*': %J\n",
				length(keys(rpcd)), length(keys(sso)), uncovered));
			// Known, reported difference: rpcd's "*" also matches the non-luci
			// group "unauthenticated", whose access-group marker SSO admin does
			// not get (its scopes are covered by the raw ubus "*"). Anything else
			// uncovered is drift.
			assert.match([ "access-group unauthenticated read" ], uncovered, `SSO admin lacks rights an rpcd '*' login has: ${join(", ", uncovered)}`);
		});
	});
});
