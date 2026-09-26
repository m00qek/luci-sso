'use strict';

import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as Result from 'luci_sso.result';
import { UBUS_SESSION_FAILED, UBUS_ERROR, CRYPTO_INIT_FAILED, INVALID_TOKEN, SYSTEM_ERROR, TOKEN_REPLAYED } from 'luci_sso.errors';

/**
 * Logic for interacting with UBUS sessions.
 */

const ACL_DIR = "/usr/share/rpcd/acl.d";

/**
 * Loads every access-group definition from rpcd's ACL directory.
 *
 * Returns `{ entries, groups }`. `entries` has one item per (file, group,
 * permission) with a usable section: `{ group, perm, section }`, where perm is
 * "read" or "write" and section maps scopes to objects. `groups` lists every
 * group name defined with an object value, sections or not. A group may be defined in several
 * files; each definition yields its own entries, as rpcd applies them all.
 * Unparseable files, non-object roots, group values and sections, and keys
 * other than "read" and "write" are skipped. Files are read in name order,
 * like rpcd's glob.
 * @private
 */
function _load_acl_entries(deps) {
	let files = deps.fs.lsdir(ACL_DIR);
	if (!files) {
		deps.log("error", `ACL scan failed: ${ACL_DIR} is missing or unreadable`);
		return Result.err("ACL_SCAN_FAILED");
	}

	let entries = [], groups = {};
	for (let f in sort(files)) {
		if (!match(f, /\.json$/)) continue;

		let content = deps.fs.readfile(`${ACL_DIR}/${f}`);
		if (!content) continue;

		let res = encoding.safe_json(content);
		if (!res.ok || type(res.data) != "object") continue;

		for (let group, def in res.data) {
			if (type(def) != "object") continue;
			groups[group] = true;
			for (let perm in [ "read", "write" ]) {
				if (type(def[perm]) == "object")
					push(entries, { group, perm, section: def[perm] });
			}
		}
	}
	return Result.ok({ entries, groups: sort(keys(groups)) });
};

// fnmatch(3) without flags, as rpcd matches role lists against group names:
// `*` and `?` are wildcards and `[...]` is a character class ([!...] negates).
function _glob_regexp(pattern) {
	let out = "^";
	for (let i = 0; i < length(pattern); i++) {
		let ch = substr(pattern, i, 1);
		if (ch == "*") out += ".*";
		else if (ch == "?") out += ".";
		else if (ch == "[") {
			let j = index(substr(pattern, i + 1), "]");
			if (j < 1) { out += "\\["; continue; }
			let body = substr(pattern, i + 1, j);
			if (substr(body, 0, 1) == "!") body = "^" + substr(body, 1);
			out += "[" + replace(body, /\\/g, "\\\\") + "]";
			i += j + 1;
		}
		else out += (index("\\.^$|+(){}]", ch) >= 0) ? "\\" + ch : ch;
	}
	return regexp(out + "$");
}

// A role list entry matches a group. Hardening beyond rpcd: a pattern with a
// wildcard only ever matches "luci-*" groups, so `*` cannot reach groups such
// as "unauthenticated" or a third-party package's own groups.
function _entry_matches(pattern, group) {
	if (match(pattern, /[*?\[]/) && !match(group, /^luci-/)) return false;
	return match(group, _glob_regexp(pattern)) != null;
}

// rpc_login_test_permission: negations ("!pattern") are checked first and
// deny; then any positive entry allows.
function _list_permits(list, group) {
	if (type(list) != "array") return false;
	for (let p in list) {
		if (type(p) != "string" || substr(p, 0, 1) != "!") continue;
		// rpcd skips whitespace after '!' only, not trailing whitespace.
		let neg = ltrim(substr(p, 1));
		if (length(neg) && _entry_matches(neg, group)) return false;
	}
	for (let p in list) {
		if (type(p) != "string" || !length(p) || substr(p, 0, 1) == "!") continue;
		if (_entry_matches(p, group)) return true;
	}
	return false;
}

// Write implies read, exactly as in rpcd.
function _role_permits(perms, perm, group) {
	if (_list_permits(perms[perm], group)) return true;
	return (perm == "read") ? _list_permits(perms.write, group) : false;
}

/**
 * Expands a role into the grants rpcd gives a password login whose rpcd login
 * entry has the same `read`/`write` lists (rpc_login_setup_acl_file).
 * test/system/rpcd_parity_test.uc compares the result with a real rpcd
 * password login on every CI run, so a change in rpcd's rules fails CI:
 *   - for every permitted (group, perm) section, each scope is granted:
 *       table notation  "<scope>": { "<object>": [ "<function>", ... ] }
 *       array notation  "<scope>": [ "<object>", ... ]   (function = perm)
 *   - plus "access-group" <group> <perm> once the section has any scope,
 *     which LuCI's UI checks.
 * Returns a de-duplicated list of [scope, object, function].
 * @private
 */
function _expand_role(entries, perms) {
	let seen = {}, grants = [];
	let add = (scope, obj, fn) => {
		let k = `${scope}\n${obj}\n${fn}`;
		if (seen[k]) return;
		seen[k] = true;
		push(grants, [ scope, obj, fn ]);
	};

	for (let e in entries) {
		if (!_role_permits(perms, e.perm, e.group)) continue;
		for (let scope, spec in e.section) {
			if (type(spec) == "object") {
				for (let obj, fns in spec) {
					if (type(fns) != "array") continue;
					for (let fn in fns) {
						if (type(fn) == "string") add(scope, obj, fn);
					}
				}
			} else if (type(spec) == "array") {
				for (let obj in spec) {
					if (type(obj) == "string") add(scope, obj, e.perm);
				}
			}
			add("access-group", e.group, e.perm);
		}
	}
	return grants;
}

// Issues grants with one session.grant call per scope.
function _grant_all(deps, sid, grants) {
	let by_scope = {};
	for (let g in grants) {
		if (!by_scope[g[0]]) by_scope[g[0]] = [];
		push(by_scope[g[0]], [ g[1], g[2] ]);
	}
	for (let scope, objects in by_scope) {
		let res = deps.ubus.call("session", "grant", { ubus_rpc_session: sid, scope, objects });
		if (!res.ok)
			deps.log("warn", `UBUS session grant failed [sid: ${crypto.safe_id(deps.native, sid)}] [scope: ${scope}] [objects: ${length(objects)}]`);
	}
}

/**
 * Idle timeout used when LuCI's own setting is unavailable. Matches the
 * luci.sauth.sessiontime default that OpenWrt ships.
 */
const DEFAULT_SESSION_TIMEOUT = 3600;

/**
 * Returns the rpcd session timeout to use: LuCI's configured
 * `luci.sauth.sessiontime`, the same value LuCI passes to `session login`
 * for password logins, so SSO and password sessions behave alike. rpcd
 * treats it as an idle timeout: each access resets it.
 *
 * Falls back to DEFAULT_SESSION_TIMEOUT when deps.uci is absent or the
 * option is missing or not a positive integer.
 * @private
 */
function _session_timeout(deps) {
	if (!deps.uci) return DEFAULT_SESSION_TIMEOUT;
	let t = int(deps.uci.get("luci", "sauth", "sessiontime"));
	return (type(t) == "int" && t > 0) ? t : DEFAULT_SESSION_TIMEOUT;
};

/**
 * Creates a real LuCI system session via UBUS WITHOUT a password.
 *
 * @param {object} deps - { fs, ubus, uci, log, clock }; uci is optional
 * @param {string} username - Target system username (e.g. root)
 * @param {object} perms - Permissions object { read: [], write: [] }
 * @param {string} oidc_email - The real user's email for tagging
 * @param {string} access_token - OIDC access token to persist
 * @param {string} refresh_token - OIDC refresh token to persist
 * @param {string} id_token - OIDC ID token to persist (for logout)
 * @returns {object} - Result Object {ok, data/error}
 */
export function create_passwordless_session(deps, username, perms, oidc_email, access_token, refresh_token, id_token) {
	if (type(deps.ubus) != "object" || type(deps.ubus.call) != "function") {
		die("CONTRACT_VIOLATION: ubus.create_passwordless_session requires deps.ubus.call");
	}

	// 1. Create a raw session
	let res_create = deps.ubus.call("session", "create", { timeout: _session_timeout(deps) });
	if (!res_create.ok || !res_create.data.ubus_rpc_session) {
		deps.log("error", "UBUS session creation failed");
		return Result.err(UBUS_SESSION_FAILED);
	}

	let sid = res_create.data.ubus_rpc_session;

	// 2. Grant Permissions
	let grant_perm = (scope, obj, func) => {
		let res = deps.ubus.call("session", "grant", {
			ubus_rpc_session: sid,
			scope: scope,
			objects: [[obj, func]]
		});
		if (!res.ok) {
			deps.log("warn", `UBUS session grant failed [sid: ${crypto.safe_id(deps.native, sid)}] [scope: ${scope}] [obj: ${obj}] [func: ${func}]`);
		}
	};
	// write '*' is full admin: unrestricted ubus/uci/file/cgi-io plus read and
	// write on every luci-* access group (LuCI's UI checks those), plus read on
	// the "unauthenticated" group, whose marker an rpcd '*' login also carries.
	//
	// Every other role gets exactly what rpcd would grant a password login
	// with the same read/write lists: each permitted access group's ACL
	// sections are expanded into concrete scope grants (see _expand_role).
	// Granting only the access-group names is not enough: rpcd checks ubus and
	// uci calls against the concrete scopes, which it expands only at login.
	let write_all = false;
	for (let w in (perms.write || [])) if (w === "*") write_all = true;

	let acl_res = _load_acl_entries(deps);
	if (!acl_res.ok) {
		deps.log("error", `Failed to load LuCI ACLs for role [sid: ${crypto.safe_id(deps.native, sid)}]`);
		deps.ubus.call("session", "destroy", { ubus_rpc_session: sid });
		return Result.err(UBUS_SESSION_FAILED);
	}
	let entries = acl_res.data.entries;

	if (write_all) {
		grant_perm("ubus", "*", "*");
		grant_perm("uci", "*", "*");
		grant_perm("file", "*", "*");
		grant_perm("cgi-io", "*", "*");

		let all = filter(acl_res.data.groups, (g) => match(g, /^luci-/));
		let admin = [];
		for (let mode in [ "read", "write" ]) {
			for (let g in all)
				push(admin, [ "access-group", g, mode ]);
		}
		// An rpcd '*' login also matches the non-luci "unauthenticated" group.
		// Its calls are already covered by the raw ubus '*' above; the marker
		// keeps admin sessions identical to rpcd's for anything that checks it.
		if (index(acl_res.data.groups, "unauthenticated") != -1)
			push(admin, [ "access-group", "unauthenticated", "read" ]);
		_grant_all(deps, sid, admin);
	} else {
		// A named group that no ACL file defines grants nothing: say so.
		let known = {};
		for (let g in acl_res.data.groups) known[g] = true;
		for (let list in [ perms.read, perms.write ]) {
			for (let n in (list || [])) {
				if (type(n) == "string" && !match(n, /^!|[*?\[]/) && !known[n])
					deps.log("warn", `Role grants unknown access group '${n}'; no ACL file defines it`);
			}
		}

		// Baseline: every session also reads the "unauthenticated" group, which
		// is what rpcd grants an anonymous client (session access/login,
		// luci.getFeatures). LuCI's views call those; a root password login gets
		// them through its read '*' glob, but luci-sso's wildcards skip non-luci
		// groups on purpose, so name the group explicitly.
		let with_baseline = { read: [ ...(perms.read || []), "unauthenticated" ], write: perms.write };
		_grant_all(deps, sid, _expand_role(entries, with_baseline));
	}

	// 3. Generate CSRF token
	let res_csrf = crypto.random(deps.native, 32);
	if (!res_csrf.ok) {
		deps.log("error", "CRITICAL: CSPRNG failure during CSRF token generation");
		return Result.err(CRYPTO_INIT_FAILED);
	}
	let csrf_res = encoding.b64url_encode(res_csrf.data);
	if (!csrf_res.ok) {
		deps.log("error", "CRITICAL: b64url_encode failure during CSRF token generation");
		return Result.err(CRYPTO_INIT_FAILED);
	}
	let csrf_token = csrf_res.data;

	// 4. Set session variables. Without them the session has no CSRF token and
	// no username, so a failure here must not hand back a usable session.
	let res_set = deps.ubus.call("session", "set", {
		ubus_rpc_session: sid,
		values: {
			username: username,
			oidc_user: oidc_email,
			oidc_access_token: access_token,
			oidc_refresh_token: refresh_token,
			oidc_id_token: id_token,
			token: csrf_token
		}
	});
	if (!res_set.ok) {
		deps.log("error", `UBUS session set failed [sid: ${crypto.safe_id(deps.native, sid)}]`);
		deps.ubus.call("session", "destroy", { ubus_rpc_session: sid });
		return Result.err(UBUS_SESSION_FAILED);
	}

	deps.log("info", `Successful Passwordless SSO login for [oidc_id: ${crypto.safe_id(deps.native, oidc_email)}] mapped to ${username}`);

	return Result.ok(sid);
};

/**
 * Retrieves session data from UBUS.
 *
 * @param {object} deps - { ubus, log }
 * @param {string} sid - UBUS session ID
 * @returns {object} - Result Object {ok, data/error}
 */
export function get_session(deps, sid) {
	if (type(deps.ubus) != "object" || type(deps.ubus.call) != "function") return Result.err("UBUS_UNAVAILABLE");
	if (!sid || type(sid) != "string") return Result.err("INVALID_SID");

	let res = deps.ubus.call("session", "get", { ubus_rpc_session: sid });
	if (!res.ok || type(res.data.values) != "object") {
		return Result.err("SESSION_NOT_FOUND");
	}

	return Result.ok(res.data.values);
};

const TOKEN_REGISTRY_DIR = "/var/run/luci-sso/tokens";

/**
 * Atomically registers an access token to prevent replay.
 * Uses atomic filesystem directory creation as a lock.
 *
 * @param {object} deps - { fs, log }
 * @param {string} access_token - Token to register
 * @returns {object} - Result Object {ok, error}
 */
export function register_token(deps, access_token) {
	try {
		if (!access_token || type(access_token) != "string") return Result.err(INVALID_TOKEN);

		// 1. Ensure registry exists
		try { deps.fs.mkdir(TOKEN_REGISTRY_DIR, 0700); } catch(e) {}

		// 2. Generate a unique cryptographic ID for the token (64-char hex digest)
		let res_h = crypto.hash_sha256_hex(deps.native, access_token);
		if (!res_h.ok) return res_h;

		let token_id = res_h.data;
		let lock_path = `${TOKEN_REGISTRY_DIR}/${token_id}`;

		// 3. ATOMIC: Try to create the directory. This is an atomic "test-and-set" in POSIX.
		if (deps.fs.mkdir(lock_path, 0700)) {
			return Result.ok();
		}
		return Result.err(TOKEN_REPLAYED);
	} catch (e) {
		deps.log("error", `Exception in register_token: ${e}`);
		return Result.err(SYSTEM_ERROR, e);
	}
};

/**
 * Destroys a LuCI system session via UBUS.
 *
 * @param {object} deps - { ubus, log }
 * @param {string} sid - UBUS session ID
 * @returns {object} - Result Object {ok, error}
 */
export function destroy_session(deps, sid) {
	if (type(deps.ubus) != "object" || type(deps.ubus.call) != "function") return Result.err("UBUS_UNAVAILABLE");
	if (!sid || type(sid) != "string") return Result.err("INVALID_SID");

	let res = deps.ubus.call("session", "destroy", { ubus_rpc_session: sid });
	if (!res.ok) {
		return Result.err(UBUS_ERROR, res.error);
	}
	return Result.ok();
};
