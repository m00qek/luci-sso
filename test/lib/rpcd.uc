'use strict';

// Helpers for the system bucket, which drives the container's REAL rpcd.
//
// rpcd reloads (SIGHUP: it saves its sessions, re-executes itself and restores
// them) whenever the luci-sso ubus object writes an entry. While it restarts,
// its ubus objects are briefly gone, so a test that writes must wait for the
// reload to finish before its next call. The system bucket runs its files one
// at a time (devenv/scripts/test.sh), so no other file sees the restart.

import * as ubus_lib from 'ubus';
import * as uci from 'uci';

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

/** Deletes a section of /etc/config/rpcd if it exists (no reload). */
export function drop_section(section) {
	let cur = rpcd_cursor();
	if (cur.get("rpcd", section)) {
		cur.delete("rpcd", section);
		cur.commit("rpcd");
	}
};

/** The effective ACLs of a session, flattened to { "scope object function": true }. */
export function acls_of(conn, sid) {
	let l = conn.call("session", "list", { ubus_rpc_session: sid });
	let out = {};
	for (let scope, objs in (l ? l.acls : null) || {})
		for (let obj, fns in objs)
			for (let fn in fns)
				out[`${scope} ${obj} ${fn}`] = true;
	return out;
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

export function has_marker(conn, sid) {
	return !!acls_of(conn, sid)["luci-sso-test marker x"];
};

/**
 * Runs fn(conn), which must make rpcd reload, and returns its result once the
 * reload is over: a session without a username has lost its marker grant and
 * the luci-sso object is back on ubus. Dies after `timeout_ms`.
 */
export function await_reload(conn, fn, timeout_ms) {
	let canary = marked_session(conn, null);
	let res = fn(conn);
	// A call that reaches rpcd while it restarts is never answered, so poll on
	// a connection that gives up after a second instead of the default 30.
	let poll = ubus_lib.connect(null, 1);
	let waited = 0, limit = timeout_ms || 10000;
	while (true) {
		let listed = poll.list("luci-sso");
		if (listed && length(listed) && !has_marker(poll, canary))
			break;
		if (waited >= limit)
			die(`rpcd did not reload within ${limit} ms`);
		sleep(100);
		waited += 100;
	}
	conn.call("session", "destroy", { ubus_rpc_session: canary });
	return res;
};

export function connect() {
	return ubus_lib.connect();
};
