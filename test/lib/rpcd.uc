'use strict';

// Helpers for the system bucket, which drives the container's REAL rpcd and
// procd.
//
// rpcd reloads (SIGHUP: it saves its sessions, re-executes itself and restores
// them) whenever an apply of /etc/config/rpcd changes a role's rpcd login
// entry (/etc/init.d/luci-sso, through its procd trigger), and when a test
// signals it. While it restarts, its ubus objects are briefly gone, so a test
// that makes it reload must wait for the reload to finish before its next
// call. The system bucket runs its
// files one at a time (devenv/scripts/test.sh), so no other file sees the
// restart.

import * as ubus_lib from 'ubus';
import * as uci from 'uci';
import * as rpcd_login from 'luci_sso.rpcd_login';

export const ENTRY_PREFIX = "luci_sso_";

/** A fresh cursor, so every read sees /etc/config/rpcd as it is now. */
export function rpcd_cursor() {
	return uci.cursor();
};

/** Every login section of /etc/config/rpcd, in order, as get_all returns it. */
export function rpcd_sections() {
	let out = [];
	rpcd_cursor().foreach("rpcd", null, (s) => push(out, s));
	return out;
};

/** Writes an rpcd login entry directly through UCI (no reload). */
export function put_login(section, values) {
	let cur = rpcd_cursor();
	cur.set("rpcd", section, "login");
	for (let k, v in values) cur.set("rpcd", section, k, v);
	cur.commit("rpcd");
};

/**
 * A luci-sso role matching one made-up email, and its rpcd login entry with
 * the given { read, write } lists, as the settings page stages them
 * (rpcd_login.entry and stage: `unauthenticated` added to the read list),
 * committed without an apply: no trigger and no rpcd reload. Returns the entry.
 */
export function put_role(name, lists) {
	let cur = rpcd_cursor();
	cur.set("luci-sso", name, "role");
	cur.set("luci-sso", name, "email", [ `${name}@systest.invalid` ]);
	cur.commit("luci-sso");
	let res = rpcd_login.entry(name, lists.read || [], lists.write || []);
	if (!res.ok)
		die(`put_role ${name}: ${res.details}`);
	rpcd_login.stage(cur, res.data);
	cur.commit("rpcd");
	return res.data;
};

/** Deletes a section of /etc/config/rpcd if it exists (no reload). */
export function drop_section(section) {
	let cur = rpcd_cursor();
	if (cur.get("rpcd", section)) {
		cur.delete("rpcd", section);
		cur.commit("rpcd");
	}
};

/** Deletes a luci-sso role and its rpcd login entry, if they exist (no reload). */
export function drop_role(name) {
	let cur = rpcd_cursor();
	if (cur.get("luci-sso", name)) {
		cur.delete("luci-sso", name);
		cur.commit("luci-sso");
	}
	drop_section(rpcd_login.section_name(name));
};

// A session's ACLs flattened to { "scope object function": true }, or null
// when the session list call fails: rpcd is restarting, or has no such session.
function flat_acls(conn, sid) {
	let l = conn.call("session", "list", { ubus_rpc_session: sid });
	if (l == null)
		return null;
	let out = {};
	for (let scope, objs in l.acls || {})
		for (let obj, fns in objs)
			for (let fn in fns)
				out[`${scope} ${obj} ${fn}`] = true;
	return out;
}

/**
 * The effective ACLs of a session, flattened to { "scope object function": true }.
 * Dies when rpcd does not answer, so a call that fails is never read as a
 * session without rights.
 */
export function acls_of(conn, sid) {
	let acls = flat_acls(conn, sid);
	if (acls == null)
		die(`session list failed for a session: ${conn.error()}`);
	return acls;
};

/**
 * A session with the given username (or none) and one marker grant that no
 * login entry can produce. The marker is gone once rpcd has reloaded.
 */
export function marked_session(conn, username) {
	let sid = conn.call("session", "create", { timeout: 300 }).ubus_rpc_session;
	if (username != null)
		conn.call("session", "set", { ubus_rpc_session: sid, values: { username } });
	conn.call("session", "grant", { ubus_rpc_session: sid, scope: "luci-sso-test", objects: [ [ "marker", "x" ] ] });
	return sid;
};

const MARKER = "luci-sso-test marker x";

// Milliseconds on the monotonic clock since `since`.
function elapsed_ms(since) {
	let t = clock(true);
	return t[0] * 1000 + t[1] / 1000000 - since;
}

export function has_marker(conn, sid) {
	return !!acls_of(conn, sid)[MARKER];
};

/**
 * Runs fn(conn), which must make rpcd reload, and returns its result once the
 * reload is over: the new rpcd answers for the canary session, which it
 * restored without its marker grant, and the luci-sso object is on ubus.
 *
 * Only an answer counts. While rpcd restarts, the session object is briefly
 * gone ("Not found") or the old process never answers, and neither may be
 * taken for a marker that is gone. The new rpcd answers only once it has
 * restored every session (it queues calls until then), so an answer without
 * the marker means the restored sessions are in place. Dies after
 * `timeout_ms`: 10 s, several times the second or so a reload takes here.
 */
export function await_reload(conn, fn, timeout_ms) {
	let canary = marked_session(conn, null);
	let res = fn(conn);
	// A call that reaches rpcd while it restarts is never answered, so poll on
	// a connection that gives up after a second instead of the default 30.
	let poll = ubus_lib.connect(null, 1);
	let limit = timeout_ms || 10000, start = elapsed_ms(0);
	while (true) {
		let listed = poll.list("luci-sso");
		let acls = flat_acls(poll, canary);
		if (listed && length(listed) && acls != null && !acls[MARKER])
			break;
		if (elapsed_ms(start) >= limit)
			die(`rpcd did not reload within ${limit} ms`);
		sleep(100);
	}
	conn.call("session", "destroy", { ubus_rpc_session: canary });
	return res;
};

/**
 * Waits until rpcd has reloaded since `canary` was made by marked_session():
 * rpcd answers for it, without its marker. Dies after `timeout_ms`.
 */
export function await_marker_gone(canary, timeout_ms) {
	let poll = ubus_lib.connect(null, 1);
	let limit = timeout_ms || 15000, start = elapsed_ms(0);
	while (true) {
		let listed = poll.list("luci-sso");
		let acls = flat_acls(poll, canary);
		if (listed && length(listed) && acls != null && !acls[MARKER])
			return;
		if (elapsed_ms(start) >= limit)
			die(`rpcd did not reload within ${limit} ms`);
		sleep(100);
	}
};

/**
 * Polls fn() every 100 ms until it returns a truthy value, and returns it.
 * Dies after `timeout_ms` with `what` in the message.
 */
export function wait_for(what, fn, timeout_ms) {
	let limit = timeout_ms || 15000, start = elapsed_ms(0);
	while (true) {
		let v = fn();
		if (v)
			return v;
		if (elapsed_ms(start) >= limit)
			die(`timed out after ${limit} ms waiting for ${what}`);
		sleep(100);
	}
};

export function connect() {
	return ubus_lib.connect();
};
