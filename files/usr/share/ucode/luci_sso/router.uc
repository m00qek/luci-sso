import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as session from 'luci_sso.session';
import { parse_params } from 'luci_sso.utils';

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
 * Creates an error response.
 * @private
 */
function error_response(msg, status) {
	return response(status || 500, ["Content-Type: text/plain"], msg);
}

/**
 * Handles the initial login redirect.
 * @private
 */
function handle_login(io, config) {
	let disc_res = oidc.discover(io, config.issuer_url);
	if (!disc_res.ok) return error_response(`OIDC Discovery failed: ${disc_res.error}`, 500);

	let handshake_res = session.create_state(io);
	if (!handshake_res.ok) return error_response(`Failed to create handshake: ${handshake_res.error}`, 500);
	let handshake = handshake_res.data;

	let url = oidc.get_auth_url(io, config, disc_res.data, handshake);

	return response(302, [
		`Location: ${url}`,
		`Set-Cookie: luci_sso_state=${handshake.token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300`
	]);
}

/**
 * Handles the OIDC callback.
 * @private
 */
function handle_callback(io, config, request) {
	let query = parse_params(request.query_string);
	let cookies = parse_params(request.http_cookie, ";");

	if (!query.code) return error_response("Missing authorization code", 400);

	// 1. Verify Handshake State Cookie
	let state_token = cookies.luci_sso_state;
	if (!state_token) return error_response("Missing handshake cookie (session timeout?)", 401);

	let handshake_res = session.verify_state(io, state_token);
	if (!handshake_res.ok) return error_response(`Invalid handshake: ${handshake_res.error}`, 401);
	let handshake = handshake_res.data;

	// 2. Validate binding
	if (query.state != handshake.state) return error_response("State mismatch (CSRF protection)", 403);

	// 3. Discovery
	let disc_res = oidc.discover(io, config.issuer_url);
	if (!disc_res.ok) return error_response(`OIDC Discovery failed: ${disc_res.error}`, 500);
	let discovery = disc_res.data;

	// 4. Exchange
	let exchange_res = oidc.exchange_code(io, config, discovery, query.code, handshake.code_verifier);
	if (!exchange_res.ok) return error_response(`Token exchange failed: ${exchange_res.error}`, 500);
	let tokens = exchange_res.data;

	// 5. Verify ID Token
	let jwks_res = oidc.fetch_jwks(io, discovery.jwks_uri);
	if (!jwks_res.ok) return error_response(`Failed to fetch IdP keys: ${jwks_res.error}`, 500);

	let verify_res = oidc.verify_id_token(io, tokens, jwks_res.data, config, handshake);
	if (!verify_res.ok) return error_response(`ID Token verification failed: ${verify_res.error}`, 401);
	let user_data = verify_res.data;

	// 6. Session
	let session_res = session.create(io, user_data);
	if (!session_res.ok) return error_response("Failed to create application session", 500);

	return response(302, [
		"Location: /cgi-bin/luci/",
		`Set-Cookie: luci_sso_session=${session_res.data}; HttpOnly; Secure; SameSite=Strict; Path=/`,
		"Set-Cookie: luci_sso_state=; HttpOnly; Secure; Path=/; Max-Age=0"
	]);
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

	return error_response("Not Found", 404);
};
