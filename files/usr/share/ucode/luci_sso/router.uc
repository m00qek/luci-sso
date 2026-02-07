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
 * Creates an error response and logs it.
 * @private
 */
function error_response(io, msg, status) {
	if (io && io.log) io.log("error", `${status || 500}: ${msg}`);
	return response(status || 500, { "Content-Type": "text/plain" }, msg);
}

/**
 * Handles the initial login redirect.
 * @private
 */
function handle_login(io, config) {
	let disc_res = oidc.discover(io, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	if (!disc_res.ok) return error_response(io, `OIDC Discovery failed: ${disc_res.error}`, 500);

	// Ensure system is initialized (bootstrap secret key if needed)
	let key_res = session.get_secret_key(io);
	if (!key_res.ok) return error_response(io, `System initialization failed: ${key_res.error}`, 500);

	let handshake_res = session.create_state(io);
	if (!handshake_res.ok) return error_response(io, `Failed to create handshake: ${handshake_res.error}`, 500);
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
		return { ok: false, error: `Identity Provider error: ${query.error}`, status: 400 };
	}

	if (!query.code) {
		return { ok: false, error: "Missing authorization code", status: 400 };
	}

	let state_token = cookies.luci_sso_state;
	if (!state_token) {
		return { ok: false, error: "Missing handshake cookie (session timeout?)", status: 401 };
	}

	let handshake_res = session.verify_state(io, state_token, config.clock_tolerance);
	if (!handshake_res.ok) {
		return { ok: false, error: `Invalid handshake: ${handshake_res.error}`, status: 401 };
	}

	let handshake = handshake_res.data;
	if (query.state != handshake.state) {
		return { ok: false, error: "State mismatch (CSRF protection)", status: 403 };
	}

	return { ok: true, data: { code: query.code, handshake: handshake } };
}

/**
 * Executes the full OIDC exchange and verification flow.
 * @private
 */
function complete_oauth_flow(io, config, code, handshake) {
	let disc_res = oidc.discover(io, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	if (!disc_res.ok) {
		return { ok: false, error: `OIDC Discovery failed: ${disc_res.error}`, status: 500 };
	}
	// Create a shallow copy to avoid mutating the cached object
	let discovery = { ...disc_res.data };

	// Backchannel Override: The Router must talk to the IdP via the internal network,
	// even if the Discovery document (meant for the browser) uses the public URL.
	if (config.internal_issuer_url != config.issuer_url) {
		discovery.token_endpoint = replace(discovery.token_endpoint, config.issuer_url, config.internal_issuer_url);
		discovery.jwks_uri = replace(discovery.jwks_uri, config.issuer_url, config.internal_issuer_url);
	}

	let exchange_res = oidc.exchange_code(io, config, discovery, code, handshake.code_verifier);
	if (!exchange_res.ok) {
		return { ok: false, error: `Token exchange failed: ${exchange_res.error}`, status: 500 };
	}
	let tokens = exchange_res.data;

	let jwks_res = oidc.fetch_jwks(io, discovery.jwks_uri);
	if (!jwks_res.ok) {
		return { ok: false, error: `Failed to fetch IdP keys: ${jwks_res.error}`, status: 500 };
	}

	let verify_res = oidc.verify_id_token(io, tokens, jwks_res.data, config, handshake, discovery);
	
	// Key Rotation / Stale Cache Recovery: 
	// If verification fails due to signature, re-fetch JWKS without cache and try one more time.
	if (!verify_res.ok && verify_res.error == "INVALID_SIGNATURE") {
		if (io.log) io.log("warn", "ID Token signature verification failed; forcing JWKS refresh and retrying");
		jwks_res = oidc.fetch_jwks(io, discovery.jwks_uri, { force: true });
		if (jwks_res.ok) {
			verify_res = oidc.verify_id_token(io, tokens, jwks_res.data, config, handshake, discovery);
		}
	}

	if (!verify_res.ok) {
		return { ok: false, error: `ID Token verification failed: ${verify_res.error}`, status: 401 };
	}

	return { ok: true, data: verify_res.data };
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
function create_session_response(io, mapping, oidc_email) {
	let ubus_res = ubus.create_session(io, mapping.rpcd_user, mapping.rpcd_password, oidc_email);
	if (!ubus_res.ok) {
		return { ok: false, error: "System login failed (UBUS)", status: 500 };
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
	let val_res = validate_callback_request(io, config, request);
	if (!val_res.ok) return error_response(io, val_res.error, val_res.status);
	let code = val_res.data.code;
	let handshake = val_res.data.handshake;

	let oauth_res = complete_oauth_flow(io, config, code, handshake);
	if (!oauth_res.ok) return error_response(io, oauth_res.error, oauth_res.status);
	let user_data = oauth_res.data;

	let mapping = find_user_mapping(io, config, user_data.email);
	if (!mapping) {
		return error_response(io, `User ${user_data.email} is not authorized on this device`, 403);
	}

	let final_res = create_session_response(io, mapping, user_data.email);
	if (!final_res.ok) return error_response(io, final_res.error, final_res.status);

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
	if (type(io) != "object" || type(config) != "object" || type(request) != "object") {
		die("CONTRACT_VIOLATION: router.handle expects (io, config, request)");
	}

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

	return error_response(io, "Not Found", 404);
};