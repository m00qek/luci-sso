import * as crypto from 'luci_sso.crypto';

/**
 * Logic for interacting with UBUS sessions.
 */

/**
 * Creates a real LuCI system session via UBUS.
 * 
 * @param {object} io - I/O provider (must have ubus_call and log)
 * @param {string} username - RPCD username
 * @param {string} password - RPCD password
 * @param {string} oidc_email - The real user's email for tagging
 * @param {string} access_token - OIDC access token to persist
 * @param {string} refresh_token - OIDC refresh token to persist
 * @returns {object} - Result Object {ok, data/error}
 */
export function create_session(io, username, password, oidc_email, access_token, refresh_token) {
	if (type(io.ubus_call) != "function") {
		die("CONTRACT_VIOLATION: ubus.create_session requires io.ubus_call");
	}

	// 1. Perform standard login to get ACLs
	let login_res = io.ubus_call("session", "login", {
		username: username,
		password: password,
		timeout: 3600
	});

	if (!login_res || !login_res.ubus_rpc_session) {
		io.log("error", `UBUS login failed for template user '${username}'`);
		return { ok: false, error: "UBUS_LOGIN_FAILED" };
	}

	let sid = login_res.ubus_rpc_session;

	// 2. Generate a random CSRF token (required by LuCI for write actions)
	let csrf_token = crypto.b64url_encode(crypto.random(16));

	// 3. Authorize and tag the session
	io.ubus_call("session", "set", {
		ubus_rpc_session: sid,
		values: { 
			username: username,
			oidc_user: oidc_email,
			oidc_access_token: access_token,
			oidc_refresh_token: refresh_token,
			token: csrf_token 
		}
	});

	io.log("info", `Successful SSO login for [oidc_id: ${crypto.safe_id(oidc_email)}] mapped to system user ${username}`);

	return { ok: true, data: sid };
};

const TOKEN_REGISTRY_DIR = "/var/run/luci-sso/tokens";

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
