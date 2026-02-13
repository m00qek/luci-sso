import * as crypto from 'luci_sso.crypto';

/**
 * Logic for interacting with UBUS sessions.
 */

/**
 * Internal helper to grant all LuCI access groups to a session.
 * Scans /usr/share/rpcd/acl.d/ for luci-* patterns.
 * @private
 */
function _grant_all_luci_acls(io, sid) {
	let acl_dir = "/usr/share/rpcd/acl.d";
	let files = io.lsdir(acl_dir);
	if (!files) return;

	for (let f in files) {
		if (!match(f, /\.json$/)) continue;

		let content = io.read_file(`${acl_dir}/${f}`);
		if (!content) continue;

		// Simple regex to find "luci-..." strings that are used as keys
		// This matches what gen_session.sh does
		let groups = [];
		let matches = match(content, /"luci-[^"]+"/g);
		if (matches) {
			for (let m in matches) {
				// Strip quotes
				let g = substr(m[0], 1, length(m[0]) - 2);
				push(groups, g);
			}
		}

		if (length(groups) > 0) {
			io.ubus_call("session", "grant", {
				ubus_rpc_session: sid,
				scope: "access-group",
				objects: map(groups, (g) => [g, "read"]),
			});
			io.ubus_call("session", "grant", {
				ubus_rpc_session: sid,
				scope: "access-group",
				objects: map(groups, (g) => [g, "write"]),
			});
		}
	}
}

/**
 * Creates a real LuCI system session via UBUS WITHOUT a password.
 * 
 * @param {object} io - I/O provider
 * @param {string} username - Target system username (e.g. root)
 * @param {object} perms - Permissions object { read: [], write: [] }
 * @param {string} oidc_email - The real user's email for tagging
 * @param {string} access_token - OIDC access token to persist
 * @param {string} refresh_token - OIDC refresh token to persist
 * @param {string} id_token - OIDC ID token to persist (for logout)
 * @returns {object} - Result Object {ok, data/error}
 */
export function create_passwordless_session(io, username, perms, oidc_email, access_token, refresh_token, id_token) {
	if (type(io.ubus_call) != "function") {
		die("CONTRACT_VIOLATION: ubus.create_passwordless_session requires io.ubus_call");
	}

	// 1. Create a raw session
	let create_res = io.ubus_call("session", "create", { timeout: 3600 });
	if (!create_res || !create_res.ubus_rpc_session) {
		io.log("error", "UBUS session creation failed");
		return { ok: false, error: "UBUS_SESSION_FAILED" };
	}

	let sid = create_res.ubus_rpc_session;

	// 2. Grant Permissions
	let grant_perm = (scope, obj, func) => {
		io.ubus_call("session", "grant", {
			ubus_rpc_session: sid,
			scope: scope,
			objects: [[obj, func]]
		});
	};

	let is_admin = false;
	for (let r in perms.read) { if (r == "*") { is_admin = true; break; } }
	if (!is_admin) {
		for (let w in perms.write) { if (w == "*") { is_admin = true; break; } }
	}

	// If wildcard is detected, we grant full internal access and skip granular access-groups
	if (is_admin) {
		grant_perm("ubus", "*", "*");
		grant_perm("uci", "*", "*");
		grant_perm("file", "*", "*");
		grant_perm("cgi-io", "*", "*");
		
		// LuCI specific: Expand and grant all known access-groups
		_grant_all_luci_acls(io, sid);
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
		io.log("error", "CRITICAL: CSPRNG failure during CSRF token generation");
		return { ok: false, error: "CRYPTO_SYSTEM_FAILURE" };
	}
	let csrf_token = crypto.b64url_encode(res_csrf.data);

	// 4. Set session variables
	io.ubus_call("session", "set", {
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

	io.log("info", `Successful Passwordless SSO login for [oidc_id: ${crypto.safe_id(oidc_email)}] mapped to ${username}`);

	return { ok: true, data: sid };
};

/**
 * Retrieves session data from UBUS.
 * 
 * @param {object} io - I/O provider
 * @param {string} sid - UBUS session ID
 * @returns {object} - Result Object {ok, data/error}
 */
export function get_session(io, sid) {
	if (type(io.ubus_call) != "function") return { ok: false, error: "UBUS_UNAVAILABLE" };
	if (!sid || type(sid) != "string") return { ok: false, error: "INVALID_SID" };

	let res = io.ubus_call("session", "get", { ubus_rpc_session: sid });
	if (!res || type(res.values) != "object") {
		return { ok: false, error: "SESSION_NOT_FOUND" };
	}

	return { ok: true, data: res.values };
};

const TOKEN_REGISTRY_DIR = "/var/run/luci-sso/tokens";

/**
 * Removes old token replay files.
 * @param {object} io - I/O provider
 */
export function reap_stale_tokens(io) {
	let files = io.lsdir(TOKEN_REGISTRY_DIR);
	if (!files) return;

	let now = io.time();
	let max_age = 86400; // 24 hours (Used tokens are re-playable after this)

	for (let f in files) {
		let path = `${TOKEN_REGISTRY_DIR}/${f}`;
		let st = io.stat(path);
		// Note: we use directories for atomic locking
		if (st && st.mtime && (now - st.mtime) > max_age) {
			try { io.remove(path); } catch (e) {}
		}
	}
};

/**
 * Atomically registers an access token to prevent replay.
 * Uses atomic filesystem directory creation as a lock.
 * 
 * @param {object} io - I/O provider
 * @param {string} access_token - Token to register
 * @returns {boolean} - True if registration succeeded (first use), false if replayed.
 */
export function register_token(io, access_token) {
	try {
		if (!access_token || type(access_token) != "string") return false;

		// 1. Ensure registry exists
		try { io.mkdir(TOKEN_REGISTRY_DIR, 0700); } catch(e) {}

		// 2. Generate a unique safe ID for the token
		let token_id = crypto.safe_id(access_token);
		let lock_path = `${TOKEN_REGISTRY_DIR}/${token_id}`;

		// 3. ATOMIC: Try to create the directory. This is an atomic "test-and-set" in POSIX.
		if (io.mkdir(lock_path, 0700)) {
			return true;
		}
	} catch (e) {
		io.log("error", `Exception in register_token: ${e}`);
	}

	return false;
};

/**
 * Destroys a LuCI system session via UBUS.
 * 
 * @param {object} io - I/O provider
 * @param {string} sid - UBUS session ID
 * @returns {boolean} - True if call succeeded
 */
export function destroy_session(io, sid) {
	if (type(io.ubus_call) != "function") return false;
	if (!sid || type(sid) != "string") return false;

	io.ubus_call("session", "destroy", { ubus_rpc_session: sid });
	return true;
};
