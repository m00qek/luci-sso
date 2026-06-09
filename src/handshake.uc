'use strict';

import * as crypto from 'luci_sso.crypto';
import * as oidc from 'luci_sso.oidc';
import * as session from 'luci_sso.session';
import * as ubus from 'luci_sso.ubus';
import * as discovery from 'luci_sso.discovery';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import * as config_mod from 'luci_sso.config';
import { IDP_ERROR, MISSING_CODE, MISSING_HANDSHAKE_COOKIE, STATE_PARAMETER_MISMATCH, OIDC_DISCOVERY_FAILED, JWKS_FETCH_FAILED, ID_TOKEN_VERIFICATION_FAILED, IDENTITY_MISMATCH, TOKEN_REPLAYED, TOKEN_REGISTRY_ERROR, USER_NOT_AUTHORIZED, UBUS_LOGIN_FAILED, SYSTEM_INIT_FAILED } from 'luci_sso.errors';

/**
 * Orchestration logic for the OIDC Login Handshake.
 * Bridges the gap between raw OIDC protocol and LuCI session management.
 */

function make_session_deps(io) {
	return {
		fs: {
			readfile:  (p)    => io.read_file(p),
			writefile: (p, d) => io.write_file(p, d),
			mkdir:     (p, m) => io.mkdir(p, m),
			unlink:    (p)    => io.remove(p),
			rename:    (o, n) => io.rename(o, n),
			stat:      (p)    => io.stat(p),
			chmod:     (p, m) => io.chmod(p, m),
			lsdir:     (p)    => io.lsdir(p),
			error:     ()     => io.fserror()
		},
		clock: { time: () => io.time(), sleep: (s) => io.sleep(s) },
		log: io.log
	};
}

/**
 * Validates the raw callback request and extracts query/handshake.
 * @private
 */
function _validate_callback_request(io, config, request) {
	let query = request.query || {};
	let cookies = request.cookies || {};

	if (query.error) {
		return Result.err(IDP_ERROR, { http_status: 400 });
	}

	if (!query.code) {
		return Result.err(MISSING_CODE, { http_status: 400 });
	}

	let state_token = cookies["__Host-luci_sso_state"];
	if (!state_token) {
		return Result.err(MISSING_HANDSHAKE_COOKIE, { http_status: 401 });
	}

	let handshake_res = session.verify_state(make_session_deps(io), state_token, config.clock_tolerance);
	if (!handshake_res.ok) {
		return Result.err(handshake_res.error, { http_status: 401 });
	}

	let handshake = handshake_res.data;
	if (!crypto.constant_time_eq(query.state, handshake.state)) {
		return Result.err(STATE_PARAMETER_MISMATCH, { http_status: 403 });
	}

	return Result.ok({ code: query.code, handshake: handshake, token: state_token });
};

/**
 * Executes the full OIDC exchange and verification flow.
 * @private
 */
function _complete_oauth_flow(io, config, code, handshake, policy) {
	let session_id = handshake.id;
	let disc_res = discovery.discover(io, config.issuer_url, { internal_issuer_url: config.internal_issuer_url });
	if (!disc_res.ok) {
		return Result.err(OIDC_DISCOVERY_FAILED, { http_status: 500 });
	}
	// Create a shallow copy to avoid mutating the cached object
	let discovery_doc = { ...disc_res.data };

	// Back-Channel Override: The Router must talk to the IdP via the internal network
	if (config.internal_issuer_url != config.issuer_url) {
		let replace_origin = (url, old_origin, new_origin) => {
			if (type(url) != "string") return url;
			let norm_url_res = encoding.normalize_url(url);
			let norm_old_res = encoding.normalize_url(old_origin);
			
			if (!norm_url_res.ok || !norm_old_res.ok) return url;
			let norm_url = norm_url_res.data;
			let norm_old = norm_old_res.data;

			// Check if the normalized URL starts with the normalized old origin
			if (substr(norm_url, 0, length(norm_old)) == norm_old) {
				// We need to find where norm_old ends in the ORIGINAL url
				// Since normalize_url only lowercases scheme/host and strips trailing slashes,
				// we can find the end of the host.
				let m = match(url, /^([A-Za-z]+:\/\/)([^/]+)(.*)$/);
				if (m) {
					let raw_origin = m[1] + m[2];
					let norm_raw_origin_res = encoding.normalize_url(raw_origin);
					if (norm_raw_origin_res.ok && norm_raw_origin_res.data == norm_old) {
						return new_origin + m[3];
					}
				}
			}
			return url;
		};

		discovery_doc.token_endpoint = replace_origin(discovery_doc.token_endpoint, config.issuer_url, config.internal_issuer_url);
		discovery_doc.jwks_uri = replace_origin(discovery_doc.jwks_uri, config.issuer_url, config.internal_issuer_url);
		if (discovery_doc.userinfo_endpoint) {
			discovery_doc.userinfo_endpoint = replace_origin(discovery_doc.userinfo_endpoint, config.issuer_url, config.internal_issuer_url);
		}
	}

	let exchange_res = oidc.exchange_code(io, config, discovery_doc, code, handshake.code_verifier, session_id);
	if (!exchange_res.ok) {
		return exchange_res;
	}
	let tokens = exchange_res.data;

	let jwks_res = discovery.fetch_jwks(io, discovery_doc.jwks_uri);
	if (!jwks_res.ok) {
		return Result.err(JWKS_FETCH_FAILED, { http_status: 500 });
	}

	let verify_res = oidc.verify_id_token(io, tokens, jwks_res.data, config, handshake, discovery_doc, io.time(), policy);

	// Key Rotation Recovery
	if (!verify_res.ok) {
		let should_retry = false;
		if (verify_res.error == "KEY_NOT_FOUND") {
			should_retry = true;
		} else if (verify_res.error == "INVALID_SIGNATURE") {
			let parts = split(tokens.id_token, ".");
			let res_h = encoding.safe_json(encoding.b64url_decode(parts[0]));
			if (res_h.ok && res_h.data.kid) {
				should_retry = true;
			}
		}

		if (should_retry) {
			io.log("info", `Unrecognized or stale key detected [session_id: ${session_id}]; forcing JWKS refresh`);
			jwks_res = discovery.fetch_jwks(io, discovery_doc.jwks_uri, { force: true });
			if (jwks_res.ok) {
				verify_res = oidc.verify_id_token(io, tokens, jwks_res.data, config, handshake, discovery_doc, io.time(), policy);
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

	// FALLBACK: If email is missing from ID Token, try UserInfo endpoint (OIDC §5.3)
	if (!user_data.email && discovery_doc.userinfo_endpoint) {
		let ui_res = oidc.fetch_userinfo(io, discovery_doc.userinfo_endpoint, tokens.access_token);
		if (ui_res.ok) {
			// SECURITY: sub MUST match (OIDC Core §5.3.2)
			// MANDATORY: Use constant-time comparison for identity binding
			// W1 Hardening: Use normalization to handle case-inconsistent IdPs
			let res_norm_ui = encoding.normalize_sub(ui_res.data.sub);
			let res_norm_id = encoding.normalize_sub(user_data.sub);

			if (!res_norm_ui.ok || !res_norm_id.ok || !crypto.constant_time_eq(res_norm_ui.data, res_norm_id.data)) {
				io.log("error", `UserInfo 'sub' mismatch [session_id: ${session_id}]`);
				return Result.err(IDENTITY_MISMATCH, { http_status: 403 });
			}
			user_data.email = ui_res.data.email;

			if (!user_data.name && ui_res.data.name) {
				user_data.name = ui_res.data.name;
			}

			if (length(user_data.groups) == 0 && type(ui_res.data.groups) == "array") {
				user_data.groups = ui_res.data.groups;
			}

			io.log("info", `Claims successfully supplemented via UserInfo [session_id: ${session_id}]`);
		} else {
			io.log("warn", `UserInfo fallback failed [session_id: ${session_id}]: ${ui_res.error}`);
		}
	}

	io.log("info", `ID Token successfully validated for [sub_id: ${crypto.safe_id(user_data.sub)}] [session_id: ${session_id}]`);

	// MANDATORY: Register token AFTER verification (DoS Prevention)
	let access_token = tokens.access_token;
	let reg_res = ubus.register_token(io, access_token);
	if (!reg_res.ok) {
		if (reg_res.error == "TOKEN_REPLAYED") {
			io.log("warn", `Replay attack detected: access token already registered [session_id: ${session_id}]`);
			return Result.err(TOKEN_REPLAYED, { http_status: 403 });
		}
		io.log("error", `Access token registry write failed [session_id: ${session_id}]: ${reg_res.error}`);
		return Result.err(TOKEN_REGISTRY_ERROR, { http_status: 500 });
	}

	// W2: Warn if access token lifetime exceeds the 24h replay protection window
	let a_parts = split(access_token, ".");
	if (length(a_parts) == 3) {
		let res_ap = encoding.safe_json(encoding.b64url_decode(a_parts[1]));
		if (res_ap.ok && res_ap.data.exp && res_ap.data.iat) {
			if ((res_ap.data.exp - res_ap.data.iat) > 86400) {
				io.log("warn", `Access token lifetime exceeds 24h replay window [session_id: ${session_id}]`);
			}
		}
	}

	return Result.ok({ 
		data: user_data, 
		access_token: tokens.access_token,
		refresh_token: tokens.refresh_token,
		id_token: tokens.id_token
	});
};

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
	if (!disc_res.ok) return Result.err(OIDC_DISCOVERY_FAILED, { http_status: 500 });

	// Ensure system is initialized (bootstrap secret key if needed)
	let key_res = session.get_secret_key(make_session_deps(io));
	if (!key_res.ok) return Result.err(SYSTEM_INIT_FAILED, { http_status: 500 });

	let handshake_res = session.create_state(make_session_deps(io));
	if (!handshake_res.ok) return handshake_res;
	let handshake = handshake_res.data;

	let url_res = oidc.get_auth_url(io, config, disc_res.data, handshake);
	if (!url_res.ok) return url_res;

	return Result.ok({
		url: url_res.data,
		token: handshake.token
	});
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
	let session_id = handshake.id;

	let oauth_res = _complete_oauth_flow(io, config, code, handshake, policy);
	if (!oauth_res.ok) {
		if (oauth_res.details) {
			io.log("error", `OAuth flow failed [session_id: ${session_id}]: ${oauth_res.error} (${oauth_res.details})`);
		}
		return oauth_res;
	}

	let user_data = oauth_res.data.data;
	let res_perms = config_mod.find_roles_for_user(config, user_data);

	if (!res_perms.ok) {
		io.log("warn", `User [sub_id: ${crypto.safe_id(user_data.sub)}] matched no roles [session_id: ${session_id}]`);
		return Result.err(USER_NOT_AUTHORIZED, { http_status: 403 });
	}

	let perms = res_perms.data;

	let ubus_res = ubus.create_passwordless_session(
		io, 
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

	io.log("info", `Session successfully created for user [sub_id: ${crypto.safe_id(user_data.sub)}] [session_id: ${session_id}] (mapped to role=${perms.role_name})`);

	return Result.ok({
		sid: ubus_res.data,
		email: user_data.email
	});
};
