import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as session from 'luci_sso.session';
import * as ubus from 'luci_sso.ubus';
import * as lucihttp from 'lucihttp';
import * as discovery from 'luci_sso.discovery';
import * as handshake from 'luci_sso.handshake';
import * as config_mod from 'luci_sso.config';

/**
 * Main CGI Router for luci-sso.
 * Handles path routing and maps protocol flow results to HTTP responses.
 */

/**
 * Creates a response object.
 * @private
 */
function response(status, headers, body) {
	return {
		status: status || 200,
		headers: headers || {},
		body: body || ""
	};
}

/**
 * Creates an error response object for the shell to render.
 * @private
 */
function error_response(code, status) {
	return {
		is_error: true,
		code: code,
		status: status || 500
	};
}

/**
 * Handles the initial login redirect.
 * @private
 */
function handle_login(io, config) {
	session.reap_stale_handshakes(io, config.clock_tolerance);
	let res = handshake.initiate(io, config);
	if (!res.ok) return error_response(res.error, res.status);

	return response(302, {
		"Location": res.data.url,
		"Set-Cookie": `__Host-luci_sso_state=${res.data.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300`
	});
}

/**
 * Handles the OIDC callback path.
 * @private
 */
function handle_callback(io, config, request, policy) {
	let res = handshake.authenticate(io, config, request, policy);
	if (!res.ok) return error_response(res.error, res.status);

	return response(302, {
		"Location": "/cgi-bin/luci/",
		"Set-Cookie": [
			`sysauth_https=${res.data.sid}; HttpOnly; Secure; SameSite=Strict; Path=/`,
			`sysauth=${res.data.sid}; HttpOnly; Secure; SameSite=Strict; Path=/`,
			"__Host-luci_sso_state=; HttpOnly; Secure; Path=/; Max-Age=0"
		]
	});
}

/**
 * Handles the logout request.
 * @private
 */
function handle_logout(io, config, request) {
	let cookies = request.cookies || {};
	let query = request.query || {};
	let sid = cookies.sysauth_https || cookies.sysauth;
	let id_token_hint = null;

	if (sid) {
		let session_res = ubus.get_session(io, sid);
		if (session_res.ok) {
			// CSRF Protection: Verify that the 'stoken' parameter matches the session token
			if (!query.stoken || !crypto.constant_time_eq(query.stoken, session_res.data.token)) {
				io.log("warn", "Logout attempt with invalid or missing CSRF token");
				return error_response("AUTH_FAILED", 403);
			}
			id_token_hint = session_res.data.oidc_id_token;
		}
		ubus.destroy_session(io, sid);
	}

	let logout_url = "/";

	// OIDC RP-Initiated Logout
	let disc_res = discovery.discover(io, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	if (disc_res.ok && disc_res.data.end_session_endpoint) {
		let end_session = disc_res.data.end_session_endpoint;
		let sep = (index(end_session, '?') == -1) ? '?' : '&';
		
		logout_url = end_session;
		if (id_token_hint) {
			logout_url += `${sep}id_token_hint=${lucihttp.urlencode(id_token_hint, 1)}`;
			sep = '&';
		}
		
		let post_logout = replace(config.redirect_uri, /^(https:\/\/[^\/]+).*/, "$1/");
		logout_url += `${sep}post_logout_redirect_uri=${lucihttp.urlencode(post_logout, 1)}`;
	}

	return response(302, {
		"Location": logout_url,
		"Set-Cookie": [
			"sysauth_https=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0",
			"sysauth=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
		]
	});
}

/**
 * Main entry point for the router.
 */
export function handle(io, config, request, policy) {
	let path = request.path || "/";
	if (substr(path, 0, 1) != "/") path = "/" + path;
	if (length(path) > 1 && substr(path, -1) == "/") path = substr(path, 0, length(path) - 1);

	if (path == "/") {
		let query = request.query || {};
		if (query.action == "enabled") {
			return response(200, { "Content-Type": "application/json" }, sprintf('{"enabled": %s}', config_mod.is_enabled(io) ? "true" : "false"));
		}
		return handle_login(io, config);
	} else if (path == "/callback") {
		return handle_callback(io, config, request, policy);
	} else if (path == "/logout") {
		return handle_logout(io, config, request);
	}

	return error_response("Not Found", 404);
};