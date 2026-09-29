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

export function connect() {
	return ubus_lib.connect();
};
