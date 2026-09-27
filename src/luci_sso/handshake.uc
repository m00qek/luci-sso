"use strict";

import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as session from 'luci_sso.session';
import * as ubus from 'luci_sso.ubus';
import * as discovery from 'luci_sso.discovery';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import * as config_mod from 'luci_sso.config';
import { IDP_ERROR, MISSING_CODE, MISSING_HANDSHAKE_COOKIE, STATE_PARAMETER_MISMATCH, OIDC_DISCOVERY_FAILED, JWKS_FETCH_FAILED, ID_TOKEN_VERIFICATION_FAILED, IDENTITY_MISMATCH, TOKEN_REPLAYED, TOKEN_REGISTRY_ERROR, USER_NOT_AUTHORIZED, UBUS_LOGIN_FAILED, INVALID_SIGNATURE, KEY_NOT_FOUND, HANDSHAKE_CAPACITY_EXCEEDED } from 'luci_sso.errors';

/**
 * Orchestration logic for the OIDC Login Handshake.
 * deps = { fs, http, ubus, log, clock }
 */

/**
 * Validates the raw callback request and extracts query/handshake.
 * @private
 */
function _validate_callback_request(deps, config, request) {
	let query = request.query || {};
	let cookies = request.cookies || {};

	// The IdP's error and error_description arrive in the query string, so
	// they are attacker-controlled: sanitise them for the log, and never echo
	// them to the page (the page only shows IDP_ERROR's fixed message).
	if (query.error) {
		let desc = query.error_description ? ` (${encoding.log_safe(query.error_description)})` : "";
		deps.log("warn", `IDP_ERROR: the IdP returned error=${encoding.log_safe(query.error)}${desc}`);
		return Result.err(IDP_ERROR, { http_status: 400 });
	}

	if (!query.code) {
		return Result.err(MISSING_CODE, { http_status: 400 });
	}

	let state_token = cookies["__Host-luci_sso_state"];
	if (!state_token) {
		return Result.err(MISSING_HANDSHAKE_COOKIE, { http_status: 401 });
	}

	// session.verify_state compares query.state BEFORE consuming the handshake,
	// so a forged callback cannot destroy a login that is still in progress.
	let handshake_res = session.verify_state(deps, state_token, query.state, config.clock_tolerance);
	if (!handshake_res.ok) {
		let status = (handshake_res.error == STATE_PARAMETER_MISMATCH) ? 403 : 401;
		return Result.err(handshake_res.error, { http_status: status });
	}

	return Result.ok({ code: query.code, handshake: handshake_res.data, token: state_token });
}

/**
 * Executes the full OIDC exchange and verification flow.
 * @private
 */
function _complete_oauth_flow(deps, config, code, handshake) {
	let session_id = handshake.id;
	let disc_res = discovery.discover(deps, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	if (!disc_res.ok) {
		return Result.err(OIDC_DISCOVERY_FAILED, { http_status: 500 });
	}
	// Create a shallow copy to avoid mutating the cached object
	let discovery_doc = { ...disc_res.data };

	// Split-horizon: the router reaches the IdP's back-channel endpoints on the
	// internal origin. Only URLs on the issuer's own origin are moved, with
	// path and query kept verbatim; endpoints on other hosts (e.g. Google's
	// googleapis.com) are left alone. The authorization and end-session
	// endpoints are browser redirects and are never rewritten.
	if (config.internal_issuer_url) {
		for (let k in [ "token_endpoint", "jwks_uri", "userinfo_endpoint" ]) {
			if (type(discovery_doc[k]) == "string")
				discovery_doc[k] = encoding.rebase_origin(discovery_doc[k], config.issuer_url, config.internal_issuer_url);
		}
	}

	let exchange_res = oidc.exchange_code(deps, config, discovery_doc, code, handshake.code_verifier, session_id);
	if (!exchange_res.ok) {
		return exchange_res;
	}
	let tokens = exchange_res.data;

	let jwks_res = discovery.fetch_jwks(deps, discovery_doc.jwks_uri);
	if (!jwks_res.ok) {
		return Result.err(JWKS_FETCH_FAILED, { http_status: 500 });
	}

	let verify_res = oidc.verify_id_token(deps, tokens, jwks_res.data, config, handshake, discovery_doc, deps.clock.time());

	// Key Rotation Recovery
	if (!verify_res.ok) {
		let should_retry = false;
		if (verify_res.error == KEY_NOT_FOUND) {
			should_retry = true;
		} else if (verify_res.error == INVALID_SIGNATURE) {
			let parts = split(tokens.id_token, ".");
			let res_h = encoding.safe_json(encoding.b64url_decode(parts[0]));
			if (res_h.ok && res_h.data.kid) {
				should_retry = true;
			}
		}

		if (should_retry) {
			deps.log("info", `Unrecognized or stale key detected [session_id: ${session_id}]; forcing JWKS refresh`);
			jwks_res = discovery.fetch_jwks(deps, discovery_doc.jwks_uri, { force: true });
			if (jwks_res.ok) {
				verify_res = oidc.verify_id_token(deps, tokens, jwks_res.data, config, handshake, discovery_doc, deps.clock.time());
			}
		}
	}

	if (!verify_res.ok) {
		return Result.err(ID_TOKEN_VERIFICATION_FAILED, {
			details: verify_res.error,
			http_status: 401
		});
	}

	let user_data = verify_res.data;

	// If the ID token carries no email, try the UserInfo endpoint (OIDC Core §5.3).
	if (!user_data.email && discovery_doc.userinfo_endpoint) {
		let ui_res = oidc.fetch_userinfo(deps, discovery_doc.userinfo_endpoint, tokens.access_token);
		if (ui_res.ok) {
			// UserInfo sub MUST match the ID token sub (OIDC Core §5.3.2), or the
			// claims could belong to a different user. Normalise case first, since
			// some IdPs are inconsistent about it.
			let res_norm_ui = encoding.normalize_sub(ui_res.data.sub);
			let res_norm_id = encoding.normalize_sub(user_data.sub);

			if (!res_norm_ui.ok || !res_norm_id.ok || res_norm_ui.data !== res_norm_id.data) {
				deps.log("error", `UserInfo 'sub' mismatch [session_id: ${session_id}]`);
				return Result.err(IDENTITY_MISMATCH, { http_status: 403 });
			}
			user_data.email = ui_res.data.email;

			if (!user_data.name && ui_res.data.name) {
				user_data.name = ui_res.data.name;
			}

			if (length(user_data.groups) == 0 && type(ui_res.data.groups) == "array") {
				user_data.groups = ui_res.data.groups;
			}

			deps.log("info", `Claims successfully supplemented via UserInfo [session_id: ${session_id}]`);
		} else {
			deps.log("warn", `UserInfo fallback failed [session_id: ${session_id}]: ${ui_res.error}`);
		}
	}

	deps.log("info", `ID Token successfully validated for [sub_id: ${crypto.safe_id(deps.native, user_data.sub)}] [session_id: ${session_id}]`);

	// Register the token only after verification, so forged tokens cannot fill the registry.
	let access_token = tokens.access_token;
	let reg_res = ubus.register_token(deps, access_token);
	if (!reg_res.ok) {
		if (reg_res.error == TOKEN_REPLAYED) {
			deps.log("warn", `Replay attack detected: access token already registered [session_id: ${session_id}]`);
			return Result.err(TOKEN_REPLAYED, { http_status: 403 });
		}
		deps.log("error", `Access token registry write failed [session_id: ${session_id}]: ${reg_res.error}`);
		return Result.err(TOKEN_REGISTRY_ERROR, { http_status: 500 });
	}

	// Warn if the access token outlives the 24h replay-registry window.
	let a_parts = split(access_token, ".");
	if (length(a_parts) == 3) {
		let res_ap = encoding.safe_json(encoding.b64url_decode(a_parts[1]));
		if (res_ap.ok && res_ap.data.exp && res_ap.data.iat) {
			if ((res_ap.data.exp - res_ap.data.iat) > 86400) {
				deps.log("warn", `Access token lifetime exceeds 24h replay window [session_id: ${session_id}]`);
			}
		}
	}

	return Result.ok({
		data: user_data,
		access_token: tokens.access_token,
		refresh_token: tokens.refresh_token,
		id_token: tokens.id_token
	});
}

/**
 * Initiates the OIDC login flow.
 *
 * @param {object} deps - { fs, http, ubus, log, clock }
 * @param {object} config - UCI configuration
 * @returns {object} - Result Object {ok, data: {url, token}}
 */
export function initiate(deps, config) {
	deps.log("info", "Initiating OIDC login flow");
	let disc_res = discovery.discover(deps, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	if (!disc_res.ok) return Result.err(OIDC_DISCOVERY_FAILED, { http_status: 500 });

	let handshake_res = session.create_state(deps, config.clock_tolerance);
	if (!handshake_res.ok) {
		// Capacity is a temporary condition, not a server fault.
		if (handshake_res.error == HANDSHAKE_CAPACITY_EXCEEDED)
			return Result.err(HANDSHAKE_CAPACITY_EXCEEDED, { http_status: 503 });
		return handshake_res;
	}
	let handshake = handshake_res.data;

	let url_res = oidc.get_auth_url(deps, config, disc_res.data, handshake);
	if (!url_res.ok) return url_res;

	return Result.ok({
		url: url_res.data,
		token: handshake.token
	});
};

/**
 * Processes the OIDC callback and creates a LuCI session.
 *
 * @param {object} deps - { fs, http, ubus, log, clock }
 * @param {object} config - UCI configuration
 * @param {object} request - Parsed request context
 * @returns {object} - Result Object {ok, data: {sid, email}}
 */
export function authenticate(deps, config, request) {
	deps.log("info", "OIDC callback received");

	let val_res = _validate_callback_request(deps, config, request);
	if (!val_res.ok) return val_res;

	let code = val_res.data.code;
	let handshake = val_res.data.handshake;
	let session_id = handshake.id;

	let oauth_res = _complete_oauth_flow(deps, config, code, handshake);
	if (!oauth_res.ok) {
		if (oauth_res.details) {
			deps.log("error", `OAuth flow failed [session_id: ${session_id}]: ${oauth_res.error} (${oauth_res.details})`);
		}
		return oauth_res;
	}

	let user_data = oauth_res.data.data;
	let res_perms = config_mod.find_roles_for_user(config, user_data);

	if (!res_perms.ok) {
		deps.log("warn", `User [sub_id: ${crypto.safe_id(deps.native, user_data.sub)}] matched no roles [session_id: ${session_id}]`);
		return Result.err(USER_NOT_AUTHORIZED, { http_status: 403 });
	}

	let perms = res_perms.data;

	let ubus_res = ubus.create_passwordless_session(
		deps,
		perms.role_name,
		perms,
		user_data.email,
		oauth_res.data.access_token,
		oauth_res.data.refresh_token,
		oauth_res.data.id_token
	);

	if (!ubus_res.ok) {
		return Result.err(UBUS_LOGIN_FAILED, { http_status: 500 });
	}

	deps.log("info", `Session successfully created for user [sub_id: ${crypto.safe_id(deps.native, user_data.sub)}] [session_id: ${session_id}] (mapped to role=${perms.role_name})`);

	return Result.ok({
		sid: ubus_res.data,
		email: user_data.email
	});
};
