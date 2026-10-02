"use strict";

import * as crypto from 'luci_sso.crypto';
import * as session from 'luci_sso.session';
import * as ubus from 'luci_sso.ubus';
import * as lucihttp from 'lucihttp';
import * as discovery from 'luci_sso.discovery';
import * as handshake from 'luci_sso.handshake';
import * as config_mod from 'luci_sso.config';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import * as ratelimit from 'luci_sso.ratelimit';
import * as rpcd_login from 'luci_sso.rpcd_login';
import { TOO_MANY_REQUESTS, SSO_DISABLED, NOT_FOUND, CSRF_CHECK_FAILED } from 'luci_sso.errors';

/**
 * Main CGI Router for luci-sso.
 * deps = { fs, http, ubus, uci, log, clock }
 */

/**
 * Where a completed login lands when it has no page to return to.
 * @private
 */
const LUCI_START = "/cgi-bin/luci/";

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
 * Handles the initial login redirect.
 * @private
 */
function handle_login(deps, config, request) {
	let reap_res = session.reap_stale_handshakes(deps, config.clock_tolerance);
	if (reap_res.ok && reap_res.data > 0) {
		deps.log("info", `Cleaned up ${reap_res.data} stale handshakes`);
	}

	// The page the user asked for (issue #27). handshake.initiate validates
	// it and keeps it in the handshake file, never in a cookie.
	let query = request.query || {};
	let res = handshake.initiate(deps, config, query.return_to);
	if (!res.ok) return res;

	return Result.ok(response(302, {
		"Location": res.data.url,
		"Set-Cookie": `__Host-luci_sso_state=${res.data.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300`
	}));
}

/**
 * Handles the OIDC callback path.
 * @private
 */
function handle_callback(deps, config, request) {
	let res = handshake.authenticate(deps, config, request);
	if (!res.ok) return res;

	// SameSite=Lax, not Strict. This is hardening, NOT the fix for issue #11 --
	// that was cookie-path shadowing, handled below. Measured: Chromium still
	// sends Strict cookies here, because it compares against the immediately
	// preceding hop and callback -> /cgi-bin/luci/ is same-site. Safari instead
	// evaluates the whole redirect chain, which begins at the IdP, and would
	// withhold a Strict cookie. Lax is correct for a cookie that has to survive
	// a return from an external IdP, and still sends nothing on cross-site
	// POST, iframe or XHR, so CSRF protection is unaffected -- the same
	// reasoning already applied to __Host-luci_sso_state above.
	return Result.ok(response(302, {
		// The page the login started from, already checked against
		// encoding.return_path by handshake.authenticate; else LuCI's start.
		"Location": res.data.return_to || LUCI_START,
		// LuCI's admin node accepts either sysauth_https or sysauth_http,
		// whatever the scheme; HTTPS only decides which one its own password
		// login sets. sysauth_http is deliberately NOT set: every cookie here
		// is Secure, so the browser sends none of them over plain HTTP, and
		// config.load() rejects a non-HTTPS issuer or redirect_uri outright.
		// What must be HTTPS is the browser's connection; uhttpd may serve
		// plain HTTP to a TLS-terminating reverse proxy (see
		// docs/explanation/security-model.md). `sysauth` is the legacy name
		// older LuCI still reads.
		"Set-Cookie": [
			`sysauth_https=${res.data.sid}; HttpOnly; Secure; SameSite=Lax; Path=/`,
			`sysauth=${res.data.sid}; HttpOnly; Secure; SameSite=Lax; Path=/`,
			// Issue #11. LuCI's own login sets these at path=build_url()
			// (/cgi-bin/luci), we set them at Path=/. Same name, different path
			// means both coexist, and RFC 6265 sends the LONGER path first —
			// LuCI reads only the first value, so a leftover cookie from an
			// earlier password login silently shadows the session we just
			// created and the user is bounced back to the login page.
			// We cannot simply adopt /cgi-bin/luci: this module's own
			// /cgi-bin/luci-sso/logout endpoint has to read the cookie, and
			// /cgi-bin/luci does not path-match /cgi-bin/luci-sso. So keep
			// Path=/ and expire the shadowing copy instead.
			"sysauth_https=; HttpOnly; Secure; Path=/cgi-bin/luci; Max-Age=0",
			"sysauth=; HttpOnly; Secure; Path=/cgi-bin/luci; Max-Age=0",
			"__Host-luci_sso_state=; HttpOnly; Secure; Path=/; Max-Age=0"
		]
	}));
}

/**
 * The `sub` of the ID Token stored in the session, for the logout log line,
 * so it names the user the way the login lines do. The token was verified at
 * login; here it is only read, never trusted. null when it cannot be read.
 * @private
 */
function id_token_sub(id_token) {
	let parts = (type(id_token) == "string") ? split(id_token, ".") : [];
	if (length(parts) != 3 || !length(parts[1])) return null;
	let claims = encoding.safe_json(encoding.b64url_decode(parts[1]));
	return (claims.ok && type(claims.data) == "object") ? claims.data.sub : null;
}

/**
 * Handles the logout request. With a null config, the configuration could
 * not be loaded: the session is still destroyed and its cookies expired, but
 * there is no IdP to send the browser to, so the logout is local only.
 * @private
 */
function handle_logout(deps, config, request) {
	let cookies = request.cookies || {};
	let query = request.query || {};
	let sid = cookies.sysauth_https || cookies.sysauth;
	let id_token_hint = null;

	if (!sid) {
		return Result.ok(response(302, { "Location": "/" }));
	}

	let session_res = ubus.get_session(deps, sid);
	if (!session_res.ok) {
		// Session expired or invalid - treat like unauthenticated
		return Result.ok(response(302, { "Location": "/" }));
	}

	// CSRF Protection: Verify that the 'stoken' parameter matches the session's CSRF token
	let provided_token = query.stoken || "";
	let session_token = session_res.data.token || "";
	if (!provided_token || !session_token || !crypto.constant_time_eq(provided_token, session_token)) {
		deps.log("warn", "Logout attempt with invalid or missing CSRF token");
		return Result.err(CSRF_CHECK_FAILED, { http_status: 403 });
	}
	id_token_hint = session_res.data.oidc_id_token;
	ubus.destroy_session(deps, sid);

	let role = rpcd_login.role_of(session_res.data.username);
	deps.log("info", `Logout for [sub_id: ${crypto.safe_id(deps.native, id_token_sub(id_token_hint))}] ` +
		(role != null ? `(role=${role})` : "(not an SSO session)"));

	let logout_url = "/";

	// OIDC RP-Initiated Logout
	let disc_res = null;
	if (config) {
		disc_res = discovery.discover(deps, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	} else {
		deps.log("warn", "Logout is local only: the configuration could not be loaded, so the IdP session is not ended");
	}
	if (disc_res && disc_res.ok && disc_res.data.end_session_endpoint) {
		let end_session = disc_res.data.end_session_endpoint;

		// The browser carries id_token_hint to this URL, so it must be HTTPS.
		if (encoding.is_https(end_session)) {
			let sep = (index(end_session, "?") == -1) ? "?" : "&";

			logout_url = end_session;
			if (id_token_hint) {
				logout_url += `${sep}id_token_hint=${lucihttp.urlencode(id_token_hint, 1)}`;
				sep = "&";
			}

			let redirect_uri = config.redirect_uri || "";
			let m = match(redirect_uri, /^(https:\/\/[^\/]+).*/);
			if (m) {
				let post_logout = m[1] + "/";
				logout_url += `${sep}post_logout_redirect_uri=${lucihttp.urlencode(post_logout, 1)}`;
			}
		}
	}
	return Result.ok(response(302, {
		"Location": logout_url,
		"Set-Cookie": [
			// Mirrors the attributes used when setting them (see handle_callback).
			"sysauth_https=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
			"sysauth=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
			// And the /cgi-bin/luci copies, for the same reason handle_callback
			// expires them: clearing only Path=/ would leave a LuCI-path cookie
			// behind, so an SSO logout would not actually end the LuCI session.
			"sysauth_https=; HttpOnly; Secure; Path=/cgi-bin/luci; Max-Age=0",
			"sysauth=; HttpOnly; Secure; Path=/cgi-bin/luci; Max-Age=0"
		]
	}));
}

/**
 * The request's path as the router dispatches on it: with a leading "/" and
 * without a trailing one.
 * @private
 */
function route_path(request) {
	let path = request.path || "/";
	if (substr(path, 0, 1) != "/") path = "/" + path;
	if (length(path) > 1 && substr(path, -1) == "/") path = substr(path, 0, length(path) - 1);
	return path;
}

/**
 * Whether the request is for the logout endpoint, which handle() serves
 * even with a null config (see handle).
 *
 * @param {object} request - The parsed request
 * @returns {boolean}
 */
export function is_logout(request) {
	return route_path(request) == "/logout";
};

/**
 * Main entry point for the router.
 *
 * `config` is null when the configuration could not be loaded (disabled
 * SSO, or a CONFIG_ERROR). Then only ?action=enabled and /logout are served:
 * logging out must never depend on the OIDC settings, so a broken
 * configuration cannot leave an SSO session alive. Every other path fails
 * with SSO_DISABLED.
 *
 * @param {object} deps - { fs, http, ubus, uci, log, clock }
 */
export function handle(deps, config, request) {
	let path = route_path(request);

	// ?action=enabled needs neither a valid config nor rate-limit budget.
	if (path == "/") {
		let query = request.query || {};
		if (query.action == "enabled") {
			let enabled_res = config_mod.is_enabled({ uci: deps.uci, log: deps.log });
			let enabled = (enabled_res.ok && enabled_res.data === true);
			return Result.ok(response(200, { "Content-Type": "application/json" }, sprintf('{"enabled": %s}', enabled ? "true" : "false")));
		}
	}

	// Per-client rate limit before anything that writes handshake state or
	// calls the IdP. GET / (the action=enabled probe returned above) starts a
	// login and also spends the client's login budget. A request from a
	// trusted reverse proxy skips both budgets: the proxy limits its clients,
	// which luci-sso cannot tell apart. The global limits below still apply.
	let key = ratelimit.client_key(request.client);
	let rl = ratelimit.is_trusted_proxy(request.client, config ? config.trusted_ranges : null)
		? ratelimit.exempt(deps, key)
		: ratelimit.check(deps, key, path == "/");
	if (!rl.allowed) {
		return Result.err(TOO_MANY_REQUESTS, { http_status: 429, retry_after: rl.retry_after });
	}

	// Logout works without a config (local logout only).
	if (path == "/logout") {
		return handle_logout(deps, config, request);
	}

	// Every remaining path needs a loaded config. Unreachable today: entry.uc
	// passes a null config only for ?action=enabled and /logout, answered
	// above. The guard stays as defence in depth against a future caller, and
	// returns what entry.uc renders for disabled SSO (500): 503 is reserved
	// for HANDSHAKE_CAPACITY_EXCEEDED.
	if (!config) {
		return Result.err(SSO_DISABLED, { http_status: 500 });
	}
	if (path == "/") {
		return handle_login(deps, config, request);
	} else if (path == "/callback") {
		return handle_callback(deps, config, request);
	}

	return Result.err(NOT_FOUND, { http_status: 404 });
};
