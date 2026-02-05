import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as session from 'luci_sso.session';
import { parse_params, parse_cookies } from 'luci_sso.utils';

/**
 * Creates a response object.
 * @private
 */
function response(status, headers, body) {
	return {
		status: status || 200,
		headers: headers || [],
		body: body || ""
	};
}

/**
 * Creates an error response and logs it.
 * @private
 */
function error_response(io, msg, status) {
	if (io.log) io.log("error", `${status || 500}: ${msg}`);
	return response(status || 500, ["Content-Type: text/plain"], msg);
}

/**
 * Handles the initial login redirect.
 * @private
 */
function handle_login(io, config) {
	let disc_res = oidc.discover(io, config.issuer_url);
	if (!disc_res.ok) return error_response(io, `OIDC Discovery failed: ${disc_res.error}`, 500);

	let handshake_res = session.create_state(io);
	if (!handshake_res.ok) return error_response(io, `Failed to create handshake: ${handshake_res.error}`, 500);
	let handshake = handshake_res.data;
	handshake.issuer_url = config.issuer_url;

	let url = oidc.get_auth_url(io, config, disc_res.data, handshake);

	return response(302, [
		`Location: ${url}`,
		`Set-Cookie: luci_sso_state=${handshake.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300`
	]);
}

/**
 * Validates the raw callback request and extracts query/handshake.
 * @private
 */
function validate_callback_request(io, request) {
	let query = parse_params(request.query_string);
	let cookies = parse_cookies(request.http_cookie);

	if (!query.code) {
		return { ok: false, error: "Missing authorization code", status: 400 };
	}

	let state_token = cookies.luci_sso_state;
	if (!state_token) {
		return { ok: false, error: "Missing handshake cookie (session timeout?)", status: 401 };
	}

	let handshake_res = session.verify_state(io, state_token);
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
	// 1. Discovery
	let issuer = handshake.issuer_url || config.issuer_url;
	let disc_res = oidc.discover(io, issuer);
	if (!disc_res.ok) {
		return { ok: false, error: `OIDC Discovery failed: ${disc_res.error}`, status: 500 };
	}
	let discovery = disc_res.data;

	// 2. Exchange
	let exchange_res = oidc.exchange_code(io, config, discovery, code, handshake.code_verifier);
	if (!exchange_res.ok) {
		return { ok: false, error: `Token exchange failed: ${exchange_res.error}`, status: 500 };
	}
	let tokens = exchange_res.data;

	// 3. Verify ID Token
	let jwks_res = oidc.fetch_jwks(io, discovery.jwks_uri);
	if (!jwks_res.ok) {
		return { ok: false, error: `Failed to fetch IdP keys: ${jwks_res.error}`, status: 500 };
	}

	let verify_res = oidc.verify_id_token(io, tokens, jwks_res.data, config, handshake);
	if (!verify_res.ok) {
		return { ok: false, error: `ID Token verification failed: ${verify_res.error}`, status: 401 };
	}

	return { ok: true, data: verify_res.data };
}

/**
 * Creates the final application session and response.
 * @private
 */
function create_session_response(io, user_data) {
	let session_res = session.create(io, user_data);
	if (!session_res.ok) {
		return { ok: false, error: "Failed to create application session", status: 500 };
	}

	return {
		ok: true,
		data: response(302, [
			"Location: /cgi-bin/luci/",
			`Set-Cookie: luci_sso_session=${session_res.data}; HttpOnly; Secure; SameSite=Strict; Path=/`,
			"Set-Cookie: luci_sso_state=; HttpOnly; Secure; Path=/; Max-Age=0"
		])
	};
}

/**
 * Handles the OIDC callback path.
 * @private
 */
function handle_callback(io, config, request) {
	// 1. Validate request and handshake
	let val_res = validate_callback_request(io, request);
	if (!val_res.ok) return error_response(io, val_res.error, val_res.status);
	let code = val_res.data.code;
	let handshake = val_res.data.handshake;

	// 2. Perform protocol exchange
	let oauth_res = complete_oauth_flow(io, config, code, handshake);
	if (!oauth_res.ok) return error_response(io, oauth_res.error, oauth_res.status);
	let user_data = oauth_res.data;

	// 3. Create session
	let final_res = create_session_response(io, user_data);
	if (!final_res.ok) return error_response(io, final_res.error, final_res.status);

	return final_res.data;
}

/**
 * Handles the logout request.
 * @private
 */
function handle_logout() {
	return response(302, [
		"Location: /",
		"Set-Cookie: luci_sso_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
	]);
}

/**
 * Main entry point for the router.
 * 
 * @param {object} io - I/O provider
 * @param {object} config - UCI configuration
 * @param {object} request - Parsed request context {path, query_string, http_cookie}
 * @returns {object} - Response Object {status, headers, body}
 */
export function handle(io, config, request) {
	if (type(io) != "object" || type(config) != "object" || type(request) != "object") {
		die("CONTRACT_VIOLATION: router.handle expects (io, config, request)");
	}

	// Strict Path Filtering
	let path = request.path || "/";
	if (substr(path, 0, 1) != "/") path = "/" + path;
	if (length(path) > 1 && substr(path, -1) == "/") path = substr(path, 0, length(path) - 1);

	if (path == "/") {
		return handle_login(io, config);
	} else if (path == "/callback") {
		return handle_callback(io, config, request);
	} else if (path == "/logout") {
		return handle_logout();
	}

	return error_response(io, "Not Found", 404);
};