import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as Result from 'luci_sso.result';
import { UBUS_SESSION_FAILED, UBUS_ERROR, CRYPTO_INIT_FAILED } from 'luci_sso.errors';

/**
 * Logic for interacting with UBUS sessions.
 */

/**
 * Internal helper to grant all LuCI access groups to a session.
 * Scans /usr/share/rpcd/acl.d/ for luci-* patterns.
 * @private
 */
function _grant_all_luci_acls(deps, sid) {
	let acl_dir = "/usr/share/rpcd/acl.d";
	let files = deps.fs.lsdir(acl_dir);
	if (!files) {
		deps.log("error", `ACL scan failed: ${acl_dir} is missing or unreadable`);
		return Result.err("ACL_SCAN_FAILED");
	}

	let granted = 0;
	for (let f in files) {
		if (!match(f, /\.json$/)) continue;

		let content = deps.fs.readfile(`${acl_dir}/${f}`);
		if (!content) continue;

		let res = encoding.safe_json(content);
		if (!res.ok || type(res.data) != "object") continue;

		let groups = [];
		for (let key, val in res.data) {
			// MANDATORY: Security Hardening (W5)
			// 1. Key MUST start with 'luci-'
			// 2. Value MUST be an object (RPCD ACL schema requirement)
			if (match(key, /^luci-/) && type(val) == "object") {
				push(groups, key);
			}
		}

		if (length(groups) > 0) {
			deps.ubus.call("session", "grant", {
				ubus_rpc_session: sid,
				scope: "access-group",
				objects: map(groups, (g) => [g, "read"]),
			});
			deps.ubus.call("session", "grant", {
				ubus_rpc_session: sid,
				scope: "access-group",
				objects: map(groups, (g) => [g, "write"]),
			});
			granted += length(groups);
		}
	}
	return Result.ok(granted);
};

/**
 * Creates a real LuCI system session via UBUS WITHOUT a password.
 *
 * @param {object} deps - { fs, ubus, log, clock }
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
	let res_create = deps.ubus.call("session", "create", { timeout: 3600 });
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
			deps.log("warn", `UBUS session grant failed [sid: ${crypto.safe_id(sid)}] [scope: ${scope}] [obj: ${obj}] [func: ${func}]`);
		}
	};
	let is_admin = false;
	for (let r in perms.read) { if (crypto.constant_time_eq(r, "*")) { is_admin = true; break; } }
	if (!is_admin) {
		for (let w in perms.write) { if (crypto.constant_time_eq(w, "*")) { is_admin = true; break; } }
	}

	// If wildcard is detected, we grant full internal access and skip granular access-groups
	if (is_admin) {
		grant_perm("ubus", "*", "*");
		grant_perm("uci", "*", "*");
		grant_perm("file", "*", "*");
		grant_perm("cgi-io", "*", "*");

		// LuCI specific: Expand and grant all known access-groups
		let acl_res = _grant_all_luci_acls(deps, sid);
		if (!acl_res.ok) {
			deps.log("error", `Failed to grant LuCI ACLs for wildcard admin [sid: ${crypto.safe_id(sid)}]`);
			deps.ubus.call("session", "destroy", { ubus_rpc_session: sid });
			return Result.err(UBUS_SESSION_FAILED);
		}
	} else {
		for (let r in perms.read) {
			grant_perm("access-group", r, "read");
		}
		for (let w in perms.write) {
			grant_perm("access-group", w, "write");
		}
	}

	// 3. Generate CSRF token
	let res_csrf = crypto.random(32);
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

	// 4. Set session variables
	deps.ubus.call("session", "set", {
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

	deps.log("info", `Successful Passwordless SSO login for [oidc_id: ${crypto.safe_id(oidc_email)}] mapped to ${username}`);

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
 * Removes old token replay files.
 * @param {object} deps - { fs, clock }
 * @returns {object} - Result Object {ok, data: count/error}
 */
export function reap_stale_tokens(deps) {
	let files = deps.fs.lsdir(TOKEN_REGISTRY_DIR);
	if (!files) return Result.ok(0);

	let now = deps.clock.time();
	let max_age = 86400; // 24 hours (Used tokens are re-playable after this)
	let reaped = 0;

	for (let f in files) {
		let path = `${TOKEN_REGISTRY_DIR}/${f}`;
		let st = deps.fs.stat(path);
		// Note: we use directories for atomic locking
		if (st && st.mtime && (now - st.mtime) > max_age) {
			try {
				deps.fs.unlink(path);
				reaped++;
			} catch (e) {}
		}
	}
	return Result.ok(reaped);
};

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
		if (!access_token || type(access_token) != "string") return Result.err("INVALID_TOKEN");

		// 1. Ensure registry exists
		try { deps.fs.mkdir(TOKEN_REGISTRY_DIR, 0700); } catch(e) {}

		// 2. Generate a unique cryptographic ID for the token (64-char hex digest)
		let res_h = crypto.hash_sha256_hex(access_token);
		if (!res_h.ok) return res_h;

		let token_id = res_h.data;
		let lock_path = `${TOKEN_REGISTRY_DIR}/${token_id}`;

		// 3. ATOMIC: Try to create the directory. This is an atomic "test-and-set" in POSIX.
		if (deps.fs.mkdir(lock_path, 0700)) {
			return Result.ok();
		}
		return Result.err("TOKEN_REPLAYED");
	} catch (e) {
		deps.log("error", `Exception in register_token: ${e}`);
		return Result.err("SYSTEM_ERROR", e);
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
