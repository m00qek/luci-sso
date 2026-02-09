import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as session from 'luci_sso.session';
import * as ubus from 'luci_sso.ubus';

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
		"Set-Cookie": `luci_sso_state=${handshake.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300`
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

	let state_token = cookies.luci_sso_state;
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
function complete_oauth_flow(io, config, code, handshake) {
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

	let jwks_res = oidc.fetch_jwks(io, discovery.jwks_uri);
	if (!jwks_res.ok) {
		return { ok: false, error: "JWKS_FETCH_FAILED", status: 500 };
	}

	let verify_res = oidc.verify_id_token(tokens, jwks_res.data, config, handshake, discovery, io.time());
	
	// Key Rotation / Stale Cache Recovery: 
	// If verification fails due to signature, re-fetch JWKS without cache and try one more time.
	if (!verify_res.ok && verify_res.error == "INVALID_SIGNATURE") {
		io.log("warn", `ID Token signature verification failed for [session_id: ${session_id}]; forcing JWKS refresh and retrying`);
		jwks_res = oidc.fetch_jwks(io, discovery.jwks_uri, { force: true });
		if (jwks_res.ok) {
			verify_res = oidc.verify_id_token(tokens, jwks_res.data, config, handshake, discovery, io.time());
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
		refresh_token: tokens.refresh_token
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
function create_session_response(io, mapping, oidc_email, access_token, refresh_token) {
	let ubus_res = ubus.create_session(io, mapping.rpcd_user, mapping.rpcd_password, oidc_email, access_token, refresh_token);
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
				"luci_sso_state=; HttpOnly; Secure; Path=/; Max-Age=0"
			]
		})
	};
}

/**
 * Handles the OIDC callback path.
 * @private
 */
function handle_callback(io, config, request) {
	io.log("info", "OIDC callback received");

	let val_res = validate_callback_request(io, config, request);
	if (!val_res.ok) return error_response(val_res.error, val_res.status);
	let code = val_res.data.code;
	let handshake = val_res.data.handshake;
	let session_id = handshake.id;

	let oauth_res = complete_oauth_flow(io, config, code, handshake);
	if (!oauth_res.ok) return error_response(oauth_res.error, oauth_res.status);
	let user_data = oauth_res.data;
	let access_token = oauth_res.access_token; // From complete_oauth_flow
	let refresh_token = oauth_res.refresh_token;

	// MANDATORY: Atomic Replay Protection (Blocker #1 in 1770660569)
	if (!ubus.register_token(io, access_token)) {
		io.log("error", `Access token replay detected for [sub_id: ${crypto.safe_id(user_data.sub)}] [session_id: ${session_id}]`);
		return error_response("AUTH_FAILED", 403);
	}

	let mapping = find_user_mapping(io, config, user_data.email);
	if (!mapping) {
		io.log("warn", `User [sub_id: ${crypto.safe_id(user_data.sub)}] not found in mapping whitelist [session_id: ${session_id}]`);
		return error_response("USER_NOT_AUTHORIZED", 403);
	}

	let final_res = create_session_response(io, mapping, user_data.email, access_token, refresh_token);
	if (!final_res.ok) return error_response(final_res.error, final_res.status);

	io.log("info", `Session successfully created for user [sub_id: ${crypto.safe_id(user_data.sub)}] [session_id: ${session_id}] (mapped to rpcd_user=${mapping.rpcd_user})`);

	return final_res.data;
}

/**
 * Handles the logout request.
 * @private
 */
function handle_logout(io, request) {
	let cookies = request.cookies || {};
	let sid = cookies.sysauth_https || cookies.sysauth;

	if (sid) {
		ubus.destroy_session(io, sid);
	}

	return response(302, {
		"Location": "/",
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
 * @returns {object} - Response Object {status, headers, body}
 */
export function handle(io, config, request) {
	// Periodic Cleanup: Stale handshakes
	session.reap_stale_handshakes(io, config.clock_tolerance);

	let path = request.path || "/";
	if (substr(path, 0, 1) != "/") path = "/" + path;
	if (length(path) > 1 && substr(path, -1) == "/") path = substr(path, 0, length(path) - 1);

	if (path == "/") {
		return handle_login(io, config);
	} else if (path == "/callback") {
		return handle_callback(io, config, request);
	} else if (path == "/logout") {
		return handle_logout(io, request);
	}

	return error_response("Not Found", 404);
};
