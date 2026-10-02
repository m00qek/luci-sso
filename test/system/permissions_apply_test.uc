import { describe, it, assert, contains } from 'utest';
import { create } from 'luci_sso.deps';
import * as ubus_mod from 'luci_sso.ubus';
import * as rpcd_login from 'luci_sso.rpcd_login';
import * as r from 'lib.rpcd';

// System bucket: putting role permissions in force on apply, with the
// container's REAL procd, rpcd and /etc/init.d/luci-sso.
//
// A role's permissions are its rpcd login entry, luci_sso_<role> in
// /etc/config/rpcd, which the settings page stages like any UCI change. Every
// apply of that file fires procd's config.change trigger, which runs
// `/etc/init.d/luci-sso reload`: when a luci_sso_* entry changed, rpcd
// reloads, so existing SSO sessions get the new rights. LuCI applies with
// `uci apply` and a rollback timer that rpcd keeps in memory, so the reload
// must wait until the apply is confirmed or rolled back; a rollback restores
// both files, and rpcd then reloads once, with the restored entries.
//
// Every role made here is named systest_apply; the devenv's own roles are
// left alone.

const ROLE = "systest_apply";
const SECTION = rpcd_login.section_name(ROLE);

const UBUS_STATUS_PERMISSION_DENIED = 6;

// procd runs the trigger a second after the event; the rpcd reload takes
// another second or two.
const APPLY_WAIT_MS = 15000;

function entry() {
	return r.rpcd_cursor().get_all("rpcd", SECTION);
}

// The entry the settings page stages for `lists`.
function generated(lists) {
	return rpcd_login.entry(ROLE, lists.read, lists.write).data;
}

// Whether the committed entry has exactly the lists the page stages for
// `lists`.
function entry_is(lists) {
	let e = entry(), want = generated(lists);
	let list = (v) => sprintf("%J", (type(v) == "array") ? v : []);
	return type(e) == "object" && e.username === want.username &&
		list(e.read) == list(want.read) && list(e.write) == list(want.write);
}

// The root password login, as LuCI's own.
function root_session(conn) {
	let login = conn.call("session", "login", { username: "root", password: "admin", timeout: 300 });
	if (!login)
		die(`root login failed: ${conn.error()}`);
	return login.ubus_rpc_session;
}

// Stages the role's entry with these lists in the session, as the settings
// page's Save does (unauthenticated added to the read list).
function stage_lists(conn, sid, lists) {
	let e = generated(lists);
	for (let opt in [ "read", "write" ]) {
		if (length(e[opt]))
			conn.call("uci", "set", { ubus_rpc_session: sid, config: "rpcd", section: SECTION, values: { [opt]: e[opt] } });
		else
			conn.call("uci", "delete", { ubus_rpc_session: sid, config: "rpcd", section: SECTION, option: opt });
	}
}

// Whether `uci apply` waits for its confirmation: rpcd answers `uci confirm`
// for another session with PERMISSION_DENIED then.
function apply_pending(conn) {
	conn.call("uci", "confirm", { ubus_rpc_session: "systest-not-the-applier" });
	return conn.error(true) == UBUS_STATUS_PERMISSION_DENIED;
}

function sso_login(conn) {
	let res = ubus_mod.create_passwordless_session(create(), ROLE, "apply@test", "at", "rt", "it");
	if (!res.ok)
		die(`SSO login for ${ROLE}: ${res.error}`);
	return res.data;
}

function can(conn, sid, perm, group) {
	return !!r.acls_of(conn, sid)[`access-group ${group} ${perm}`];
}

// Runs fn(conn, ctx) with the role absent before and after; ctx.sessions
// lists sessions to destroy. Leaves no apply pending and rpcd reloaded.
function with_role(fn) {
	let conn = r.connect(), ctx = { sessions: [] }, failure = null;
	r.drop_role(ROLE);
	try { fn(conn, ctx); } catch (e) { failure = e; }
	try {
		if (apply_pending(conn))
			r.wait_for("the apply to end", () => !apply_pending(conn), 120000);
		for (let sid in ctx.sessions)
			conn.call("session", "destroy", { ubus_rpc_session: sid });
		r.drop_role(ROLE);
	} catch (e) {
		if (failure == null) failure = e;
	}
	if (failure != null) die(failure);
}

describe('system: an apply puts the permissions in force', () => {
	it('a hand edit, committed and applied with reload_config, is in force and stays as written', () => {
		with_role((conn, ctx) => {
			r.put_role(ROLE, { read: [ "luci-base" ], write: [] });
			let sid = sso_login(conn);
			push(ctx.sessions, sid);
			assert.match(false, can(conn, sid, "write", "luci-mod-system-config"));

			let canary = r.marked_session(conn, null);
			push(ctx.sessions, canary);
			let cur = r.rpcd_cursor();
			cur.set("rpcd", SECTION, "read", [ "luci-base" ]);
			cur.set("rpcd", SECTION, "write", [ "luci-mod-system-config" ]);
			cur.commit("rpcd");
			let written = r.rpcd_cursor().get_all("rpcd", SECTION);

			system("reload_config");
			r.await_marker_gone(canary, APPLY_WAIT_MS);

			assert.match(true, can(conn, sid, "write", "luci-mod-system-config"), "the session has the new rights");
			assert.match(true, can(conn, sid, "read", "luci-base"), "and keeps the others");
			assert.match(written, r.rpcd_cursor().get_all("rpcd", SECTION), "the entry is as written: no unauthenticated added, nothing rewritten");
			assert.match(contains({ username: `sso:${ROLE}`, oidc_user: "apply@test" }),
				conn.call("session", "get", { ubus_rpc_session: sid }).values, "and the session keeps its values");

			let fresh = sso_login(conn);
			push(ctx.sessions, fresh);
			assert.match(sort(keys(r.acls_of(conn, fresh))), sort(keys(r.acls_of(conn, sid))),
				"the same rights as a new login");
		});
	});

	it("LuCI's unchecked apply (uci apply without rollback): the same", () => {
		with_role((conn, ctx) => {
			r.put_role(ROLE, { read: [ "*" ], write: [ "*" ] });
			let sid = sso_login(conn);
			push(ctx.sessions, sid);
			assert.match(true, can(conn, sid, "write", "luci-base"));

			let root = root_session(conn);
			push(ctx.sessions, root);
			stage_lists(conn, root, { read: [ "luci-base" ], write: [] });
			let canary = r.marked_session(conn, null);
			push(ctx.sessions, canary);
			conn.call("uci", "apply", { ubus_rpc_session: root, rollback: false });

			r.await_marker_gone(canary, APPLY_WAIT_MS);
			assert.match(true, entry_is({ read: [ "luci-base" ], write: [] }));
			assert.match(false, can(conn, sid, "write", "luci-base"), "write '*' is gone from the open session");
			assert.match(true, can(conn, sid, "read", "luci-base"));
			assert.match(true, can(conn, sid, "read", "unauthenticated"), "LuCI's baseline stays");
		});
	});

	it("deleting a role and its entry leaves its open sessions no rights", () => {
		with_role((conn, ctx) => {
			r.put_role(ROLE, { read: [ "*" ], write: [] });
			let sid = sso_login(conn);
			push(ctx.sessions, sid);

			let root = root_session(conn);
			push(ctx.sessions, root);
			conn.call("uci", "delete", { ubus_rpc_session: root, config: "luci-sso", section: ROLE });
			conn.call("uci", "delete", { ubus_rpc_session: root, config: "rpcd", section: SECTION });
			let canary = r.marked_session(conn, null);
			push(ctx.sessions, canary);
			conn.call("uci", "apply", { ubus_rpc_session: root, rollback: false });

			r.await_marker_gone(canary, APPLY_WAIT_MS);
			assert.match(null, entry());
			assert.match({}, r.acls_of(conn, sid));
		});
	});
});

describe("system: an apply with LuCI's rollback", () => {
	it('commits the entry at once, but reloads rpcd only once the apply is confirmed', () => {
		with_role((conn, ctx) => {
			r.put_role(ROLE, { read: [ "luci-base" ], write: [] });
			let sid = sso_login(conn);
			push(ctx.sessions, sid);

			let root = root_session(conn);
			push(ctx.sessions, root);
			stage_lists(conn, root, { read: [ "luci-base" ], write: [ "luci-mod-system-config" ] });
			let canary = r.marked_session(conn, null);
			push(ctx.sessions, canary);
			assert.match(null, conn.call("uci", "apply", { ubus_rpc_session: root, rollback: true, timeout: 60 }));
			assert.match(null, conn.error(), "the apply is accepted");

			assert.match(true, entry_is({ read: [ "luci-base" ], write: [ "luci-mod-system-config" ] }), "committed");
			sleep(3000);
			assert.match(true, r.has_marker(conn, canary), "no rpcd reload while the apply may still be rolled back");
			assert.match(true, apply_pending(conn), "rpcd still holds the apply");
			assert.match(false, can(conn, sid, "write", "luci-mod-system-config"), "the open session keeps its rights meanwhile");

			conn.call("uci", "confirm", { ubus_rpc_session: root });
			assert.match(null, conn.error(), "LuCI's confirmation still reaches the apply");
			r.await_marker_gone(canary, APPLY_WAIT_MS);
			assert.match(true, can(conn, sid, "write", "luci-mod-system-config"), "confirmed: the new rights are in force");
		});
	});

	it('a rollback restores the rules and the entry together, rpcd reloads once, and the session keeps its rights', () => {
		with_role((conn, ctx) => {
			let old = { read: [ "*" ], write: [ "*" ] };
			r.put_role(ROLE, old);
			let sid = sso_login(conn);
			push(ctx.sessions, sid);
			let before = sort(keys(r.acls_of(conn, sid)));

			let root = root_session(conn);
			push(ctx.sessions, root);
			conn.call("uci", "set", { ubus_rpc_session: root, config: "luci-sso", section: ROLE, values: { email: [ "changed@systest.invalid" ] } });
			stage_lists(conn, root, { read: [ "luci-base" ], write: [] });
			let canary = r.marked_session(conn, null);
			push(ctx.sessions, canary);
			conn.call("uci", "apply", { ubus_rpc_session: root, rollback: true, timeout: 5 });

			assert.match(true, entry_is({ read: [ "luci-base" ], write: [] }), "both files committed");
			assert.match([ "changed@systest.invalid" ], r.rpcd_cursor().get("luci-sso", ROLE, "email"));
			sleep(2000);
			assert.match(true, r.has_marker(conn, canary), "no reload during the apply");

			// No confirmation: rpcd rolls back after 5 s, then reloads once.
			r.wait_for("the rollback", () => !apply_pending(conn), 30000);
			r.await_marker_gone(canary, APPLY_WAIT_MS);
			assert.match(true, entry_is(old), "the previous entry");
			assert.match([ `${ROLE}@systest.invalid` ], r.rpcd_cursor().get("luci-sso", ROLE, "email"), "the previous rules");
			assert.match(before, sort(keys(r.acls_of(conn, sid))), "the session has exactly its previous rights");

			let again = r.marked_session(conn, null);
			push(ctx.sessions, again);
			sleep(3000);
			assert.match(true, r.has_marker(conn, again), "the rollback's own trigger finds nothing left to reload");
		});
	});

	// The check compares the whole of /etc/config/rpcd: an entry committed
	// without an apply has already reached the sessions that logged in since.
	it('an apply of another rpcd section reloads rpcd, and every session keeps its rights', () => {
		with_role((conn, ctx) => {
			r.put_role(ROLE, { read: [ "luci-base" ], write: [ "luci-mod-system-config" ] });
			r.await_reload(conn, () => system("/usr/libexec/luci-sso/rpcd-reload request"), 20000);
			let sid = sso_login(conn);
			push(ctx.sessions, sid);
			let before = sort(keys(r.acls_of(conn, sid)));

			let root = root_session(conn);
			push(ctx.sessions, root);
			let canary = r.marked_session(conn, null);
			push(ctx.sessions, canary);
			conn.call("uci", "add", { ubus_rpc_session: root, config: "rpcd", type: "systest", name: "systest_unrelated", values: { x: "1" } });
			conn.call("uci", "apply", { ubus_rpc_session: root, rollback: false });
			r.await_marker_gone(canary, APPLY_WAIT_MS);
			let committed = r.rpcd_cursor().get("rpcd", "systest_unrelated");
			r.drop_section("systest_unrelated");
			assert.match("systest", committed, "applied");
			assert.match(before, sort(keys(r.acls_of(conn, sid))), "the session's rights are as before");
		});
	});

	it('a deleted entry that never was applied still leaves no rights once its deletion is applied', () => {
		with_role((conn, ctx) => {
			r.put_role(ROLE, { read: [ "*" ], write: [] });
			let sid = sso_login(conn);
			push(ctx.sessions, sid);
			let root = root_session(conn);
			push(ctx.sessions, root);
			conn.call("uci", "delete", { ubus_rpc_session: root, config: "rpcd", section: SECTION });
			let canary = r.marked_session(conn, null);
			push(ctx.sessions, canary);
			conn.call("uci", "apply", { ubus_rpc_session: root, rollback: false });
			r.await_marker_gone(canary, APPLY_WAIT_MS);
			assert.match({}, r.acls_of(conn, sid));
		});
	});
});
