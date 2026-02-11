'use strict';

import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as session from 'luci_sso.session';
import * as ubus from 'luci_sso.ubus';
import * as discovery from 'luci_sso.discovery';

/**
 * Orchestration logic for the OIDC Login Handshake.
 * Bridges the gap between raw OIDC protocol and LuCI session management.
 */

/**
 * Searches the user mapping whitelist for a matching email.
 * Pure logic (no I/O).
 * @private
 */
function _find_user_mapping(config, email) {
	if (!config.user_mappings || !email) return null;
	let target = lc(email);
	for (let mapping in config.user_mappings) {
		for (let allowed in mapping.emails) {
			if (lc(allowed) == target) return mapping;
		}
	}
	return null;
}

/**
 * Validates the raw callback request and extracts query/handshake.
 * @private
 */
function _validate_callback_request(io, config, request) {
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
	if (!crypto.constant_time_eq(query.state, handshake.state)) {
		return { ok: false, error: "STATE_MISMATCH", status: 403 };
	}

	return { ok: true, data: { code: query.code, handshake: handshake, token: state_token } };
}

/**
 * Executes the full OIDC exchange and verification flow.
 * @private
 */
function _complete_oauth_flow(io, config, code, handshake, policy) {
	let session_id = handshake.id;
	let disc_res = discovery.discover(io, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	if (!disc_res.ok) {
		return { ok: false, error: "OIDC_DISCOVERY_FAILED", status: 500 };
	}
	// Create a shallow copy to avoid mutating the cached object
	let discovery_doc = { ...disc_res.data };

	// Backchannel Override: The Router must talk to the IdP via the internal network
	if (config.internal_issuer_url != config.issuer_url) {
		discovery_doc.token_endpoint = replace(discovery_doc.token_endpoint, config.issuer_url, config.internal_issuer_url);
		discovery_doc.jwks_uri = replace(discovery_doc.jwks_uri, config.issuer_url, config.internal_issuer_url);
	}

	let exchange_res = oidc.exchange_code(io, config, discovery_doc, code, handshake.code_verifier, session_id);
	if (!exchange_res.ok) {
		return exchange_res;
	}
	let tokens = exchange_res.data;
	let access_token = tokens.access_token;

	// MANDATORY: Register token BEFORE verification (Fail-Safe)
	if (!ubus.register_token(io, access_token)) {
		io.log("error", `Access token replay detected [session_id: ${session_id}]`);
		return { ok: false, error: "AUTH_FAILED", status: 403 };
	}

	// W2: Warn if access token lifetime exceeds the 24h replay protection window
	let a_parts = split(access_token, ".");
	if (length(a_parts) == 3) {
		let res_ap = crypto.safe_json(crypto.b64url_decode(a_parts[1]));
		if (res_ap.ok && res_ap.data.exp && res_ap.data.iat) {
			if ((res_ap.data.exp - res_ap.data.iat) > 86400) {
				io.log("warn", `Access token lifetime exceeds 24h replay window [session_id: ${session_id}]`);
			}
		}
	}

	let jwks_res = discovery.fetch_jwks(io, discovery_doc.jwks_uri);
	if (!jwks_res.ok) {
		return { ok: false, error: "JWKS_FETCH_FAILED", status: 500 };
	}

	let verify_res = oidc.verify_id_token(tokens, jwks_res.data, config, handshake, discovery_doc, io.time(), policy);
	
	// Key Rotation Recovery
	if (!verify_res.ok) {
		let should_retry = false;
		if (verify_res.error == "KEY_NOT_FOUND") {
			should_retry = true;
		} else if (verify_res.error == "INVALID_SIGNATURE") {
			let parts = split(tokens.id_token, ".");
			let res_h = crypto.safe_json(crypto.b64url_decode(parts[0]));
			if (!res_h.ok || !res_h.data.kid) {
				should_retry = true;
			}
		}

		if (should_retry) {
			io.log("info", `Unrecognized or stale key detected [session_id: ${session_id}]; forcing JWKS refresh`);
			jwks_res = discovery.fetch_jwks(io, discovery_doc.jwks_uri, { force: true });
			if (jwks_res.ok) {
				verify_res = oidc.verify_id_token(tokens, jwks_res.data, config, handshake, discovery_doc, io.time(), policy);
			}
		}
	}

	if (!verify_res.ok) {
		return { 
			ok: false, 
			error: "ID_TOKEN_VERIFICATION_FAILED", 
			status: 401, 
			details: verify_res.error,
			sub_details: verify_res.details
		};
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
 * Initiates the OIDC login flow.
 * 
 * @param {object} io - I/O provider
 * @param {object} config - UCI configuration
 * @returns {object} - Result Object {ok, data: {url, token}}
 */
export function initiate(io, config) {
	io.log("info", "Initiating OIDC login flow");
	let disc_res = discovery.discover(io, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	if (!disc_res.ok) return { ok: false, error: "OIDC_DISCOVERY_FAILED", status: 500 };

	// Ensure system is initialized (bootstrap secret key if needed)
	let key_res = session.get_secret_key(io);
	if (!key_res.ok) return { ok: false, error: "SYSTEM_INIT_FAILED", status: 500 };

	let handshake_res = session.create_state(io);
	if (!handshake_res.ok) return handshake_res;
	let handshake = handshake_res.data;

	let url_res = oidc.get_auth_url(io, config, disc_res.data, handshake);
	if (!url_res.ok) return url_res;

	return {
		ok: true,
		data: {
			url: url_res.data,
			token: handshake.token
		}
	};
};

/**
 * Processes the OIDC callback and creates a LuCI session.
 * 
 * @param {object} io - I/O provider
 * @param {object} config - UCI configuration
 * @param {object} request - Parsed request context
 * @param {object} [policy] - Security policy
 * @returns {object} - Result Object {ok, data: {sid, email}}
 */
export function authenticate(io, config, request, policy) {
	io.log("info", "OIDC callback received");

	let val_res = _validate_callback_request(io, config, request);
	if (!val_res.ok) return val_res;
	
	let code = val_res.data.code;
	let handshake = val_res.data.handshake;
	let state_token = val_res.data.token;
	let session_id = handshake.id;

	let oauth_res = _complete_oauth_flow(io, config, code, handshake, policy);
	if (!oauth_res.ok) {
		session.consume_state(io, state_token);
		if (oauth_res.details) {
			io.log("error", `OAuth flow failed [session_id: ${session_id}]: ${oauth_res.error} (${oauth_res.details})`);
		}
		return oauth_res;
	}

	let user_data = oauth_res.data;
	let mapping = _find_user_mapping(config, user_data.email);
	if (!mapping) {
		session.consume_state(io, state_token);
		io.log("warn", `User [sub_id: ${crypto.safe_id(user_data.sub)}] not found in mapping whitelist [session_id: ${session_id}]`);
		return { ok: false, error: "USER_NOT_AUTHORIZED", status: 403 };
	}

	let ubus_res = ubus.create_session(io, mapping.rpcd_user, mapping.rpcd_password, user_data.email, oauth_res.access_token, oauth_res.refresh_token, oauth_res.id_token);
	if (!ubus_res.ok) {
		session.consume_state(io, state_token);
		return { ok: false, error: "UBUS_LOGIN_FAILED", status: 500 };
	}

	io.log("info", `Session successfully created for user [sub_id: ${crypto.safe_id(user_data.sub)}] [session_id: ${session_id}] (mapped to rpcd_user=${mapping.rpcd_user})`);

	return {
		ok: true,
		data: {
			sid: ubus_res.data,
			email: user_data.email
		}
	};
};
