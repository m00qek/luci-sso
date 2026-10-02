import { describe, it, assert } from 'utest';
import * as fs from 'fs';
import { create } from 'luci_sso.deps';
import * as ubus_mod from 'luci_sso.ubus';
import * as r from 'lib.rpcd';

// System bucket: the package's upgrade from 0.10.0, with the container's REAL
// rpcd and the script the package runs, files/etc/uci-defaults/20-luci-sso-rpcd.
//
// 0.10.0's storage is the stable contract: matching rules in
// /etc/config/luci-sso, permissions in the luci_sso_<role> entries of
// /etc/config/rpcd. The upgrade must leave both files as they are, byte for
// byte, and every SSO session, open or new, with exactly the rights it had.
// The one exception is a global luci-sso.default.sub_issuer, which no release
// wrote: sub_issuer is an option of each role.

const UCI_DEFAULTS = "/usr/share/luci-sso/uci-defaults/20-luci-sso-rpcd";

// 0.10.0's state for four roles: no lists on the roles, and the entries its
// settings page wrote (unauthenticated appended to the read lists).
const ROLES = {
	systest_up_admin: { read: [ "*" ], write: [ "*" ] },
	systest_up_ops: { read: [ "luci-base", "luci-mod-status-*", "!luci-mod-status-logs", "unauthenticated" ], write: [ "luci-mod-system-config" ] },
	systest_up_viewer: { read: [ "unauthenticated", "luci-mod-network-*" ], write: [] },
	systest_up_none: { read: [ "unauthenticated" ], write: [] },
};

function put_v0100_state() {
	let cur = r.rpcd_cursor();
	for (let name in keys(ROLES)) {
		cur.set("luci-sso", name, "role");
		cur.set("luci-sso", name, "email", [ `${name}@systest.invalid` ]);
	}
	cur.commit("luci-sso");
	for (let name, lists in ROLES) {
		let values = { username: `sso:${name}` };
		if (length(lists.read)) values.read = lists.read;
		if (length(lists.write)) values.write = lists.write;
		r.put_login(`${r.ENTRY_PREFIX}${name}`, values);
	}
}

function files() {
	return { luci_sso: fs.readfile("/etc/config/luci-sso"), rpcd: fs.readfile("/etc/config/rpcd") };
}

// Every session's rights, by role.
function rights_of(conn, sessions) {
	let out = {};
	for (let name, sid in sessions)
		out[name] = sort(keys(r.acls_of(conn, sid)));
	return out;
}

// Runs fn(conn, sessions) with both files restored afterwards, and the
// sessions destroyed.
function with_saved_config(fn) {
	let saved = files();
	let conn = r.connect(), sessions = {}, failure = null;
	try { fn(conn, sessions); } catch (e) { failure = e; }
	for (let name, sid in sessions)
		conn.call("session", "destroy", { ubus_rpc_session: sid });
	// No reload of rpcd may still be on its way when the files are put back.
	try { r.wait_for("the reloads to end", () => !fs.access("/var/run/luci-sso/rpcd-reload"), 30000); } catch (e) { if (failure == null) failure = e; }
	fs.writefile("/etc/config/luci-sso", saved.luci_sso);
	fs.writefile("/etc/config/rpcd", saved.rpcd);
	if (failure != null) die(failure);
}

// Opens one session per role the way 0.10.0's sessions live on: named
// sso:<role>, with rights rpcd rebuilds from the entry on a reload.
function v0100_sessions(conn, sessions) {
	for (let name in keys(ROLES))
		sessions[name] = r.marked_session(conn, `sso:${name}`);
	r.await_reload(conn, () => system("kill -HUP $(pidof rpcd)"));
}

// Runs the uci-defaults script and waits for the rpcd reload it requests.
function run_upgrade(conn, sessions) {
	let canary = r.marked_session(conn, null);
	sessions.canary = canary;
	assert.match(0, system(`sh ${UCI_DEFAULTS} >/dev/null 2>&1`), UCI_DEFAULTS);
	r.await_marker_gone(canary, 20000);
	conn.call("session", "destroy", { ubus_rpc_session: canary });
	delete sessions.canary;
}

describe('system: the upgrade from 0.10.0', () => {
	it('leaves /etc/config/luci-sso and /etc/config/rpcd byte for byte as they were', () => {
		with_saved_config((conn, sessions) => {
			put_v0100_state();
			let before = files();
			run_upgrade(conn, sessions);
			assert.match(before.luci_sso, files().luci_sso, "/etc/config/luci-sso");
			assert.match(before.rpcd, files().rpcd, "/etc/config/rpcd");
		});
	});

	it("keeps every open session's rights, and gives new logins the same", () => {
		with_saved_config((conn, sessions) => {
			put_v0100_state();
			v0100_sessions(conn, sessions);
			let before = rights_of(conn, sessions);
			for (let name in keys(ROLES))
				assert.match(true, length(before[name]) > 0, `${name}: rights from its 0.10.0 entry`);

			run_upgrade(conn, sessions);

			assert.match(before, rights_of(conn, sessions), "the same rights after the upgrade and rpcd's reload");
			for (let name in keys(ROLES)) {
				let res = ubus_mod.create_passwordless_session(create(), name, "up@test", "at", "rt", "it");
				assert.match(true, res.ok, `${name}: a new login: ${res.error}`);
				sessions[`${name}_new`] = res.data;
				assert.match(before[name], sort(keys(r.acls_of(conn, res.data))), `${name}: a new login gets the same rights`);
			}
		});
	});

	it('removes a global sub_issuer, and changes nothing else', () => {
		with_saved_config((conn, sessions) => {
			put_v0100_state();
			let before = files();
			let cur = r.rpcd_cursor();
			cur.set("luci-sso", "default", "sub_issuer", "https://idp.example.com");
			cur.commit("luci-sso");
			run_upgrade(conn, sessions);
			assert.match(null, r.rpcd_cursor().get("luci-sso", "default", "sub_issuer"));
			assert.match(before, files(), "both files as before the option was set");
		});
	});

	it('enables the init script, and a second run changes nothing', () => {
		with_saved_config((conn, sessions) => {
			put_v0100_state();
			run_upgrade(conn, sessions);
			assert.match(true, !!fs.access("/etc/rc.d/S13luci-sso"), "enabled");
			let after = files();
			run_upgrade(conn, sessions);
			assert.match(after, files());
		});
	});
});
