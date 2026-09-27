import { describe, it, assert } from 'utest';
import { create } from 'luci_sso.deps';
import * as ubus_mod from 'luci_sso.ubus';
import * as r from 'lib.rpcd';

// System bucket: runs against the REAL rpcd in the openwrt container, no mocks.
//
// An SSO session gets its rights from the role's rpcd login entry
// (luci_sso_<role>, username sso:<role>), and luci-sso grants them itself
// (ubus.uc, _expand_role), because rpcd expands an entry only for password
// logins and on reload. The group DEFINITIONS come from acl.d at every login,
// but the COMBINING RULES (write implies read, table vs array notation,
// globs, negations, which scopes) are a copy of rpcd's C code. This test is
// the guard against that copy drifting: for each shape it creates an rpcd
// password login and an SSO role entry with the SAME lists, logs in both
// ways, and requires identical effective ACLs. If a future rpcd changes its
// rules, this fails and prints the entries that differ.

const LOGIN = "ssoparity";
const ROLE = "systest_parity";

// The "unauthenticated" read that luci-sso still adds to every SSO session;
// the rpcd side names it so the comparison stays exact.
const BASELINE = [ "unauthenticated" ];

const SHAPES = [
	{ name: "read '*' only",               read: [ "*" ],                                            write: [] },
	{ name: 'a specific read group',       read: [ "luci-base" ],                                    write: [] },
	{ name: 'a specific write group',      read: [],                                                 write: [ "luci-mod-system-config" ] },
	{ name: "mixed: read '*', write one",  read: [ "*" ],                                            write: [ "luci-mod-network-config" ] },
	{ name: 'globs and negation',          read: [ "luci-mod-status-*", "!luci-mod-status-logs" ],   write: [] },
	{ name: "full admin: read '*', write '*'", read: [ "*" ],                                        write: [ "*" ] },
];

function minus(a, b) { return sort(filter(keys(a), (k) => !b[k])); }

function drop_all() {
	r.drop_section(LOGIN);
	r.drop_section(r.ENTRY_PREFIX + ROLE);
}

// Runs fn(conn, rpcd_acls, sso_acls, sso_sid) for one shape; always cleans up.
function with_both_sessions(shape, fn) {
	let conn = r.connect();
	let rpcd_sid = null, sso_sid = null, failure = null;
	try {
		drop_all();
		r.put_login(LOGIN, { username: LOGIN, password: "$p$root", read: [ ...shape.read, ...BASELINE ], write: shape.write });
		r.put_login(r.ENTRY_PREFIX + ROLE, { username: `sso:${ROLE}`, read: shape.read, write: shape.write });

		// rpcd re-reads /etc/config/rpcd on each login: no reload needed.
		let login = conn.call("session", "login", { username: LOGIN, password: "admin", timeout: 120 });
		assert.match(true, !!login, "rpcd password login for the parity user");
		rpcd_sid = login.ubus_rpc_session;

		let res = ubus_mod.create_passwordless_session(create(), ROLE, 'parity@test', 'at', 'rt', 'it');
		assert.match(true, res.ok, `SSO session: ${res.error}`);
		sso_sid = res.data;

		fn(conn, r.acls_of(conn, rpcd_sid), r.acls_of(conn, sso_sid), sso_sid);
	} catch (e) {
		failure = e;
	}
	// ucode has no `finally`: clean up, then re-raise any failure.
	if (rpcd_sid) conn.call("session", "destroy", { ubus_rpc_session: rpcd_sid });
	if (sso_sid)  conn.call("session", "destroy", { ubus_rpc_session: sso_sid });
	try { drop_all(); } catch (e) { if (failure == null) failure = e; }
	if (failure != null) die(failure);
}

describe('system: SSO sessions match rpcd password logins with the same lists', () => {
	// A function parameter, not the loop variable: ucode closures created in a
	// `for (let x in ...)` body all see the last element.
	let parity_case = (shape) => it(shape.name, () => {
		with_both_sessions(shape, (conn, rpcd, sso, sso_sid) => {
			let only_rpcd = minus(rpcd, sso), only_sso = minus(sso, rpcd);
			print(sprintf("\n    [parity] %s: %d rpcd entries, %d SSO entries\n", shape.name, length(keys(rpcd)), length(keys(sso))));
			assert.match(true, length(keys(rpcd)) > 0, "the rpcd login received grants");
			assert.match([], only_rpcd, `${shape.name}: granted by rpcd but not by luci-sso: ${join(", ", only_rpcd)}`);
			assert.match([], only_sso,  `${shape.name}: granted by luci-sso but not by rpcd: ${join(", ", only_sso)}`);

			let values = conn.call("session", "get", { ubus_rpc_session: sso_sid }).values;
			assert.match(`sso:${ROLE}`, values.username, "the SSO session is named after the entry");
		});
	});
	for (let shape in SHAPES) parity_case(shape);
});
