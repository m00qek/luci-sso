"use strict";

import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as Result from 'luci_sso.result';
import * as rpcd_login from 'luci_sso.rpcd_login';
import { UBUS_SESSION_FAILED, UBUS_ERROR, CRYPTO_INIT_FAILED, INVALID_TOKEN, SYSTEM_ERROR, TOKEN_REPLAYED, MISSING_RPCD_LOGIN, INSECURE_RPCD_LOGIN } from 'luci_sso.errors';

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
}

/**
 * Expands a login entry's `read`/`write` lists into the grants rpcd gives a
 * password login with that entry (rpc_login_setup_acl_file).
 * test/system/rpcd_parity_test.uc requires the result to equal a real rpcd
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
		if (!rpcd_login.permits(perms, e.perm, e.group)) continue;
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

// Issues grants with one session.grant call per scope. Returns false when a
// call fails: the session would then hold only part of the role's rights.
function _grant_all(deps, sid, grants) {
	let by_scope = {};
	for (let g in grants) {
		if (!by_scope[g[0]]) by_scope[g[0]] = [];
		push(by_scope[g[0]], [ g[1], g[2] ]);
	}
	for (let scope, objects in by_scope) {
		let res = deps.ubus.call("session", "grant", { ubus_rpc_session: sid, scope, objects });
		if (!res.ok) {
			deps.log("error", `UBUS session grant failed [sid: ${crypto.safe_id(deps.native, sid)}] [scope: ${scope}] [objects: ${length(objects)}]`);
			return false;
		}
	}
	return true;
}

// rpcd reads only list options: a single `option read` grants nothing.
function _as_list(v) {
	return (type(v) == "array") ? v : [];
}

/**
 * Reads the rpcd login entry of a role and returns its `{ read, write }`
 * lists. The session gets its rights from this entry now, and rpcd rebuilds
 * them from the same entry on every reload, because the session's username
 * is the entry's.
 *
 * Refuses an entry that is missing, is not a login, or names another user:
 * rpcd would not find it for the session on reload. Refuses an entry with a
 * password option, whatever its value: it could be used for a password login.
 * @private
 */
function _load_login(deps, role) {
	let section = rpcd_login.section_name(role);
	let username = rpcd_login.username(role);
	let s = deps.uci.get_all(rpcd_login.CONFIG, section);

	if (type(s) != "object" || s[".type"] != "login" || s.username !== username) {
		deps.log("error", `${MISSING_RPCD_LOGIN}: role '${role}' has no rpcd login entry '${section}' with username '${username}'`);
		return Result.err(MISSING_RPCD_LOGIN);
	}
	if (exists(s, "password")) {
		deps.log("error", `${INSECURE_RPCD_LOGIN}: rpcd login entry '${section}' of role '${role}' has a password option; remove it`);
		return Result.err(INSECURE_RPCD_LOGIN);
	}
	return Result.ok({ read: _as_list(s.read), write: _as_list(s.write) });
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
 * Falls back to DEFAULT_SESSION_TIMEOUT when the option is missing or not a
 * positive integer.
 * @private
 */
function _session_timeout(deps) {
	let t = int(deps.uci.get("luci", "sauth", "sessiontime"));
	return (type(t) == "int" && t > 0) ? t : DEFAULT_SESSION_TIMEOUT;
}

/**
 * Destroys a half-initialised session and returns the given error. Every
 * failure after `session create` goes through here, so a failed login never
 * leaves a live rpcd session behind.
 * @private
 */
function _abort_session(deps, sid, code) {
	deps.ubus.call("session", "destroy", { ubus_rpc_session: sid });
	return Result.err(code);
}

/**
 * Creates a real LuCI system session via UBUS WITHOUT a password, with the
 * rights of the role's rpcd login entry.
 *
 * The session's username is `sso:<role>`, the username of the entry
 * `luci_sso_<role>` in /etc/config/rpcd, and it is granted exactly what rpcd
 * grants a password login with that entry's lists. When rpcd reloads, it
 * rebuilds the session's rights from the same entry, so they survive.
 *
 * @param {object} deps - { fs, ubus, uci, log, native }
 * @param {string} role - The luci-sso role the user matched
 * @param {string|null} oidc_email - The user's email, stored as the label
 *   `oidc_user`; null when the user has none
 * @param {string} access_token - OIDC access token to persist
 * @param {string} refresh_token - OIDC refresh token to persist
 * @param {string} id_token - OIDC ID token to persist (for logout)
 * @returns {object} - Result Object {ok, data/error}
 */
export function create_passwordless_session(deps, role, oidc_email, access_token, refresh_token, id_token) {
	if (type(deps.ubus) != "object" || type(deps.ubus.call) != "function") {
		die("CONTRACT_VIOLATION: ubus.create_passwordless_session requires deps.ubus.call");
	}
	// A real UCI cursor is a resource, a test proxy an object.
	if (deps.uci == null) {
		die("CONTRACT_VIOLATION: ubus.create_passwordless_session requires deps.uci");
	}
	if (type(role) != "string" || !length(role)) {
		die("CONTRACT_VIOLATION: ubus.create_passwordless_session requires a role name");
	}

	// 1. Read the role's rpcd login entry and the ACL files before creating
	// anything, so a refusal leaves no session behind.
	let login_res = _load_login(deps, role);
	if (!login_res.ok) return login_res;
	let perms = login_res.data;

	let acl_res = _load_acl_entries(deps);
	if (!acl_res.ok) {
		deps.log("error", `Failed to load LuCI ACLs for role '${role}'`);
		return Result.err(UBUS_SESSION_FAILED);
	}

	// A named group that no ACL file defines grants nothing: say so.
	let known = {};
	for (let g in acl_res.data.groups) known[g] = true;
	for (let list in [ perms.read, perms.write ]) {
		for (let n in list) {
			if (type(n) == "string" && !match(n, /^!|[*?\[]/) && !known[n])
				deps.log("warn", `Role '${role}' grants unknown access group '${n}'; no ACL file defines it`);
		}
	}

	// 2. Create a raw session
	let res_create = deps.ubus.call("session", "create", { timeout: _session_timeout(deps) });
	if (!res_create.ok || !res_create.data.ubus_rpc_session) {
		deps.log("error", "UBUS session creation failed");
		return Result.err(UBUS_SESSION_FAILED);
	}

	let sid = res_create.data.ubus_rpc_session;

	// 3. Generate CSRF token
	let res_csrf = crypto.random(deps.native, 32);
	if (!res_csrf.ok) {
		deps.log("error", "CRITICAL: CSPRNG failure during CSRF token generation");
		return _abort_session(deps, sid, CRYPTO_INIT_FAILED);
	}
	let csrf_res = encoding.b64url_encode(res_csrf.data);
	if (!csrf_res.ok) {
		deps.log("error", "CRITICAL: b64url_encode failure during CSRF token generation");
		return _abort_session(deps, sid, CRYPTO_INIT_FAILED);
	}
	let csrf_token = csrf_res.data;

	// 4. Set the session variables BEFORE granting anything. On a reload rpcd
	// keeps a session's values but not its rights, which it rebuilds from the
	// login entry of the saved username. With the username set first, a reload
	// between any two of these calls leaves the session with the role's full
	// rights: rebuilt from the entry, or granted by the calls after it.
	// Without the variables the session has no CSRF token and no username, so
	// a failure here must not hand back a usable session.
	// The username makes it an SSO session (rpcd_login.role_of). The email
	// is only a label for finding the session, and is left out, not stored
	// as null, when the user has none: a user matched by group whose IdP
	// sends no email.
	let values = {
		username: rpcd_login.username(role),
		oidc_access_token: access_token,
		oidc_refresh_token: refresh_token,
		oidc_id_token: id_token,
		token: csrf_token
	};
	if (type(oidc_email) == "string" && length(oidc_email))
		values.oidc_user = oidc_email;
	let res_set = deps.ubus.call("session", "set", { ubus_rpc_session: sid, values });
	if (!res_set.ok) {
		deps.log("error", `UBUS session set failed [sid: ${crypto.safe_id(deps.native, sid)}]`);
		return _abort_session(deps, sid, UBUS_SESSION_FAILED);
	}

	// 5. Grant what rpcd grants a password login with the entry. Granting only
	// the access-group names is not enough: rpcd checks ubus and uci calls
	// against the concrete scopes, which it expands only at login. Nothing is
	// added to the lists: rpcd rebuilds the session from them alone on reload.
	// A failed grant fails the login rather than leave part of the rights.
	if (!_grant_all(deps, sid, _expand_role(acl_res.data.entries, perms)))
		return _abort_session(deps, sid, UBUS_SESSION_FAILED);

	deps.log("info", `Successful Passwordless SSO login for [oidc_id: ${crypto.safe_id(deps.native, oidc_email)}] mapped to ${rpcd_login.username(role)}`);

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
