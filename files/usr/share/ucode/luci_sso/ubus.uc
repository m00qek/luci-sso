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
 * @returns {object} - Result Object {ok, data/error}
 */
export function create_session(io, username, password, oidc_email, access_token) {
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
		if (io.log) io.log("error", `UBUS login failed for template user '${username}'`);
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
			token: csrf_token 
		}
	});

	if (io.log) {
		io.log("info", `Successful SSO login for ${oidc_email} mapped to system user ${username}`);
	}

	return { ok: true, data: sid };
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
