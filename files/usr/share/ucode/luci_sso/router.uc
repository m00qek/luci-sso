import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as session from 'luci_sso.session';
import * as ubus from 'luci_sso.ubus';
import * as lucihttp from 'lucihttp';

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
	io.log("info", "Initiating OIDC login flow");
	let disc_res = oidc.discover(io, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	if (!disc_res.ok) return error_response("OIDC_DISCOVERY_FAILED", 500);

	// Ensure system is initialized (bootstrap secret key if needed)
	let key_res = session.get_secret_key(io);
	if (!key_res.ok) return error_response("SYSTEM_INIT_FAILED", 500);

	let handshake_res = session.create_state(io);
	if (!handshake_res.ok) return error_response(handshake_res.error, 500);
	let handshake = handshake_res.data;

	let url = oidc.get_auth_url(io, config, disc_res.data, handshake);

	return response(302, {
		"Location": url,
		"Set-Cookie": `__Host-luci_sso_state=${handshake.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300`
	});
}

/**
 * Validates the raw callback request and extracts query/handshake.
 * @private
 */
function validate_callback_request(io, config, request) {
	let query = request.query || {};
	let cookies = request.cookies || {};

	if (query.error) {
		return { ok: false, error: "IDP_ERROR", status: 400 };
	}

	if (!query.code) {
		return { ok: false, error: "MISSING_CODE", status: 400 };
	}

	let state_token = cookies["__Host-luci_sso_state"];
	if (!state_token) {
		return { ok: false, error: "MISSING_HANDSHAKE_COOKIE", status: 401 };
	}

	let handshake_res = session.verify_state(io, state_token, config.clock_tolerance);
	if (!handshake_res.ok) {
		return { ok: false, error: handshake_res.error, status: 401 };
	}

	let handshake = handshake_res.data;
	if (query.state != handshake.state) {
		return { ok: false, error: "STATE_MISMATCH", status: 403 };
	}

	return { ok: true, data: { code: query.code, handshake: handshake } };
}

/**
 * Executes the full OIDC exchange and verification flow.
 * @private
 */
function complete_oauth_flow(io, config, code, handshake, policy) {
	let session_id = handshake.id;
	let disc_res = oidc.discover(io, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	if (!disc_res.ok) {
		return { ok: false, error: "OIDC_DISCOVERY_FAILED", status: 500 };
	}
	// Create a shallow copy to avoid mutating the cached object
	let discovery = { ...disc_res.data };

	// Backchannel Override: The Router must talk to the IdP via the internal network,
	// even if the Discovery document (meant for the browser) uses the public URL.
	if (config.internal_issuer_url != config.issuer_url) {
		discovery.token_endpoint = replace(discovery.token_endpoint, config.issuer_url, config.internal_issuer_url);
		discovery.jwks_uri = replace(discovery.jwks_uri, config.issuer_url, config.internal_issuer_url);
	}

	let exchange_res = oidc.exchange_code(io, config, discovery, code, handshake.code_verifier, session_id);
	if (!exchange_res.ok) {
		return exchange_res;
	}
	let tokens = exchange_res.data;
	let access_token = tokens.access_token;

	// MANDATORY: Register token BEFORE verification (Fail-Safe)
	// This ensures the token is "Consumed" even if ID token verification fails.
	if (!ubus.register_token(io, access_token)) {
		io.log("error", `Access token replay detected [session_id: ${session_id}]`);
		return { ok: false, error: "AUTH_FAILED", status: 403 };
	}

	let jwks_res = oidc.fetch_jwks(io, discovery.jwks_uri);
	if (!jwks_res.ok) {
		return { ok: false, error: "JWKS_FETCH_FAILED", status: 500 };
	}

	let verify_res = oidc.verify_id_token(io, tokens, jwks_res.data, config, handshake, discovery, io.time(), policy);
	
	// Key Rotation / Stale Cache Recovery: (Warning #8 in 1770660561)
	// We only retry if:
	// 1. The token has a 'kid' that is NOT in our current keyset.
	// 2. OR the token has NO 'kid' (primitive IdP) and verification failed.
	if (!verify_res.ok) {
		let should_retry = false;
		if (verify_res.error == "KEY_NOT_FOUND") {
			should_retry = true;
		} else if (verify_res.error == "INVALID_SIGNATURE") {
			// If signature is bad but we used a 'kid' we ALREADY have, do NOT retry (DoS protection)
			// We only retry signature failure if NO kid was used (fallback for primitive IdPs)
			let parts = split(tokens.id_token, ".");
			let header = crypto.safe_json(io, crypto.b64url_decode(parts[0]));
			if (!header || !header.kid) {
				should_retry = true;
			}
		}

		if (should_retry) {
			io.log("info", `Unrecognized or stale key detected [session_id: ${session_id}]; forcing JWKS refresh`);
			jwks_res = oidc.fetch_jwks(io, discovery.jwks_uri, { force: true });
			if (jwks_res.ok) {
				verify_res = oidc.verify_id_token(io, tokens, jwks_res.data, config, handshake, discovery, io.time(), policy);
			}
		}
	}

	if (!verify_res.ok) {
		io.log("error", `ID Token verification failed [session_id: ${session_id}]: ${verify_res.error}`);
		return { ok: false, error: "ID_TOKEN_VERIFICATION_FAILED", status: 401 };
	}

	io.log("info", `ID Token successfully validated for [sub_id: ${crypto.safe_id(verify_res.data.sub)}] [session_id: ${session_id}]`);

	return { 
		ok: true, 
		data: verify_res.data, 
		access_token: tokens.access_token,
		refresh_token: tokens.refresh_token,
		id_token: tokens.id_token
	};
}

/**
 * Searches the user mapping whitelist for a matching email.
 * @private
 */
function find_user_mapping(io, config, email) {
	if (!config.user_mappings || !email) return null;
	for (let mapping in config.user_mappings) {
		for (let allowed in mapping.emails) {
			if (allowed == email) return mapping;
		}
	}
	return null;
}

/**
 * Creates the final application session and response.
 * @private
 */
function create_session_response(io, mapping, oidc_email, access_token, refresh_token, id_token) {
	let ubus_res = ubus.create_session(io, mapping.rpcd_user, mapping.rpcd_password, oidc_email, access_token, refresh_token, id_token);
	if (!ubus_res.ok) {
		return { ok: false, error: "UBUS_LOGIN_FAILED", status: 500 };
	}

	return {
		ok: true,
		data: response(302, {
			"Location": "/cgi-bin/luci/",
			"Set-Cookie": [
				`sysauth_https=${ubus_res.data}; HttpOnly; Secure; SameSite=Strict; Path=/`,
				`sysauth=${ubus_res.data}; HttpOnly; Secure; SameSite=Strict; Path=/`,
				"__Host-luci_sso_state=; HttpOnly; Secure; Path=/; Max-Age=0"
			]
		})
	};
}

/**
 * Handles the OIDC callback path.
 * @private
 */
function handle_callback(io, config, request, policy) {
	io.log("info", "OIDC callback received");

	let val_res = validate_callback_request(io, config, request);
	if (!val_res.ok) return error_response(val_res.error, val_res.status);
	let code = val_res.data.code;
	let handshake = val_res.data.handshake;
	let session_id = handshake.id;

	let oauth_res = complete_oauth_flow(io, config, code, handshake, policy);
	if (!oauth_res.ok) return error_response(oauth_res.error, oauth_res.status);
	let user_data = oauth_res.data;
	let access_token = oauth_res.access_token; // From complete_oauth_flow
	let refresh_token = oauth_res.refresh_token;
	let id_token = oauth_res.id_token;

	let mapping = find_user_mapping(io, config, user_data.email);
	if (!mapping) {
		io.log("warn", `User [sub_id: ${crypto.safe_id(user_data.sub)}] not found in mapping whitelist [session_id: ${session_id}]`);
		return error_response("USER_NOT_AUTHORIZED", 403);
	}

	let final_res = create_session_response(io, mapping, user_data.email, access_token, refresh_token, id_token);
	if (!final_res.ok) return error_response(final_res.error, final_res.status);

	io.log("info", `Session successfully created for user [sub_id: ${crypto.safe_id(user_data.sub)}] [session_id: ${session_id}] (mapped to rpcd_user=${mapping.rpcd_user})`);

	return final_res.data;
}

/**
 * Handles the logout request.
 * @private
 */
function handle_logout(io, config, request) {
	let cookies = request.cookies || {};
	let sid = cookies.sysauth_https || cookies.sysauth;
	let id_token_hint = null;

	if (sid) {
		let session_res = ubus.get_session(io, sid);
		if (session_res.ok) {
			id_token_hint = session_res.data.oidc_id_token;
		}
		ubus.destroy_session(io, sid);
	}

	let logout_url = "/";

	// OIDC RP-Initiated Logout:
	// If we have an IdP logout endpoint, redirect there to terminate the SSO session.
	let disc_res = oidc.discover(io, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	if (disc_res.ok && disc_res.data.end_session_endpoint) {
		let end_session = disc_res.data.end_session_endpoint;
		let sep = (index(end_session, '?') == -1) ? '?' : '&';
		
		logout_url = end_session;
		if (id_token_hint) {
			logout_url += `${sep}id_token_hint=${lucihttp.urlencode(id_token_hint, 1)}`;
			sep = '&';
		}
		
		// Optional: post_logout_redirect_uri.
		// We use the root of the site.
		let post_logout = "https://" + (request.env.HTTP_HOST || "localhost") + "/";
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
 * 
 * @param {object} io - I/O provider
 * @param {object} config - UCI configuration
 * @param {object} request - Parsed request context {path, query, cookies}
 * @param {object} [policy] - Security policy (Second Dimension)
 * @returns {object} - Response Object {status, headers, body}
 */
export function handle(io, config, request, policy) {
	// Periodic Cleanup: Stale handshakes
	// NOTE: Token reaping is handled by a background cron job (/usr/sbin/luci-sso-cleanup)
	// to prevent algorithmic complexity DoS attacks on the CGI interface.
	session.reap_stale_handshakes(io, config.clock_tolerance);

	let path = request.path || "/";
	if (substr(path, 0, 1) != "/") path = "/" + path;
	if (length(path) > 1 && substr(path, -1) == "/") path = substr(path, 0, length(path) - 1);

	if (path == "/") {
		return handle_login(io, config);
	} else if (path == "/callback") {
		return handle_callback(io, config, request, policy);
	} else if (path == "/logout") {
		return handle_logout(io, config, request);
	}

	return error_response("Not Found", 404);
};
