"use strict";

import * as lucihttp from 'lucihttp';
import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import { find_jwk } from 'luci_sso.discovery';
import * as Result from 'luci_sso.result';
import { INSECURE_AUTH_ENDPOINT, INVALID_AUTH_ENDPOINT, MISSING_STATE_PARAMETER, MISSING_NONCE_PARAMETER, MISSING_PKCE_CHALLENGE, INSECURE_TOKEN_ENDPOINT, INVALID_PKCE_VERIFIER, TOKEN_ENDPOINT_NETWORK_ERROR, OIDC_INVALID_GRANT, TOKEN_EXCHANGE_FAILED, TOKEN_RESPONSE_INVALID_JSON, MISSING_ID_TOKEN, UNSUPPORTED_ALGORITHM, DISCOVERY_ISSUER_MISMATCH, MISSING_SUB_CLAIM, MISSING_EXP_CLAIM, MISSING_IAT_CLAIM, MISSING_NONCE, NONCE_MISMATCH, AZP_MISMATCH, MISSING_ACCESS_TOKEN, AT_HASH_MISMATCH, CRYPTO_ERROR, INSECURE_USERINFO_ENDPOINT, USERINFO_FETCH_FAILED, USERINFO_NETWORK_ERROR, USERINFO_INVALID_JSON, INVALID_JWT_HEADER, IDENTITY_MISMATCH } from 'luci_sso.errors';

/**
 * ID token signature algorithms this module accepts. Fixed in code rather than
 * UCI so a configuration change can never weaken it: symmetric algorithms such
 * as HS256 would allow the algorithm-confusion attack.
 */
export const ALLOWED_ALGS = ["RS256", "ES256"];

/**
 * Browser-facing status (details.http_status) for every failed back-channel
 * call to the IdP: the router acted as a gateway and the upstream failed. The
 * IdP's own status is logged here, never forwarded: a 401 from the token
 * endpoint means the router's client credentials failed, not the browser's.
 */
const BAD_GATEWAY = 502;

/** Status for a UserInfo response about a different subject (IDENTITY_MISMATCH). */
const FORBIDDEN = 403;

/**
 * Generates the authorization URL.
 */
export function get_auth_url(deps, config, discovery_doc, params) {
	// state and nonce are the CSRF and replay bindings; refuse to start without them.
	if (!params.state || type(params.state) != "string" || length(params.state) < 16) {
		return Result.err(MISSING_STATE_PARAMETER);
	}

	if (!params.nonce || type(params.nonce) != "string" || length(params.nonce) < 16) {
		return Result.err(MISSING_NONCE_PARAMETER);
	}

	if (!params.code_challenge || type(params.code_challenge) != "string") {
		return Result.err(MISSING_PKCE_CHALLENGE);
	}

	// The browser is sent here with state, nonce and challenge in the URL; never over plain HTTP.
	if (!encoding.is_https(discovery_doc.authorization_endpoint)) {
		return Result.err(INSECURE_AUTH_ENDPOINT);
	}
	
	// RFC 6749 §3.1: "The endpoint URI MUST NOT include a fragment component."
	if (index(discovery_doc.authorization_endpoint, "#") != -1) {
		return Result.err(INVALID_AUTH_ENDPOINT, "authorization_endpoint MUST NOT contain a fragment");
	}

	let query = {
		response_type: "code",
		client_id: config.client_id,
		redirect_uri: config.redirect_uri,
		scope: config.scope || "openid profile email",
		state: params.state,
		nonce: params.nonce,
		code_challenge: params.code_challenge,
		code_challenge_method: "S256"
	};
	let url = discovery_doc.authorization_endpoint;

	let sep = (index(url, "?") == -1) ? "?" : "&";
	for (let k, v in query) {
		if (v == null) continue;
		url += `${sep}${k}=${lucihttp.urlencode(v, 1)}`;
		sep = "&";
	}
	return Result.ok(url);
};

/**
 * Exchanges authorization code for tokens. The client authenticates with
 * client_secret_post (RFC 6749 §2.3.1): client_id and client_secret in the
 * form body.
 *
 * A refusal's details carry, besides http_status, the token endpoint's own
 * status (`upstream_status`) and its OAuth `error` code (`oauth_error`, or
 * null when the body has none), and a network failure's the transport cause
 * (`cause`), for the connection test. A login shows the user none of them.
 */
export function exchange_code(deps, config, discovery, code, verifier, session_id) {
	if (!encoding.is_https(discovery.token_endpoint)) return Result.err(INSECURE_TOKEN_ENDPOINT);

	// Log PKCE-bound exchanges so they can be correlated with the handshake.
	let sid_ctx = session_id ? ` [session_id: ${session_id}]` : "";
	deps.log("info", `Initiating token exchange${sid_ctx}`);

	if (type(verifier) != "string" || length(verifier) < 43 || length(verifier) > 128) {
		deps.log("error", `Rejected token exchange${sid_ctx}: PKCE verifier length out of bounds`);
		return Result.err(INVALID_PKCE_VERIFIER);
	}

	let body = {
		grant_type: "authorization_code",
		client_id: config.client_id,
		client_secret: config.client_secret,
		redirect_uri: config.redirect_uri,
		code: code,
		code_verifier: verifier
	};

	let encoded_body = "";
	let sep = "";
	for (let k, v in body) {
		if (v == null) continue;
		encoded_body += `${sep}${k}=${lucihttp.urlencode(v, 1)}`;
		sep = "&";
	}

	let res_http = deps.http.post(discovery.token_endpoint, {
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: encoded_body
	});

	if (!res_http.ok) {
		deps.log("warn", `Token exchange network error${sid_ctx}: ${Result.describe(res_http)}`);
		return Result.err(TOKEN_ENDPOINT_NETWORK_ERROR, { http_status: BAD_GATEWAY, cause: Result.describe(res_http) });
	}

	let response = res_http.data;
	if (response.status != 200) {
		// The error code (RFC 6749 §5.2) comes from the IdP: only a short one
		// made of the characters the registered codes use is kept.
		let res_err = encoding.safe_json(response.body);
		let oauth_error = (res_err.ok && type(res_err.data) == "object" && type(res_err.data.error) == "string" &&
			match(res_err.data.error, /^[A-Za-z0-9_.:-]{1,64}$/)) ? res_err.data.error : null;
		if (oauth_error == "invalid_grant") {
			deps.log("error", `Token exchange failed (invalid_grant, HTTP ${response.status})${sid_ctx}`);
			return Result.err(OIDC_INVALID_GRANT, { http_status: BAD_GATEWAY, upstream_status: response.status, oauth_error });
		}
		deps.log("warn", `Token exchange HTTP ${response.status}${sid_ctx}`);
		return Result.err(TOKEN_EXCHANGE_FAILED, { http_status: BAD_GATEWAY, upstream_status: response.status, oauth_error });
	}

	let res = encoding.safe_json(response.body);
	if (!res.ok) {
		deps.log("error", `Token exchange JSON parse error${sid_ctx}: ${res.details}`);
		return Result.err(TOKEN_RESPONSE_INVALID_JSON, { http_status: BAD_GATEWAY });
	}
	let tokens = res.data;

	deps.log("info", `Token exchange successful${sid_ctx}`);

	return Result.ok(tokens);
};

/**
 * Verifies ID Token and matches nonce.
 * 
 * @param {object} tokens - Token response {id_token, access_token}
 * @param {array} keys - JWK keyset
 * @param {object} config - UCI configuration
 * @param {object} handshake - Handshake state {nonce, ...}
 * @param {object} discovery - Discovery document
 * @param {number} now - Current timestamp
 */
export function verify_id_token(deps, tokens, keys, config, handshake, discovery, now) {
	if (!tokens.id_token || type(tokens.id_token) != "string") return Result.err(MISSING_ID_TOKEN);

	let parts = split(tokens.id_token, ".");
	let res_h = encoding.safe_json(encoding.b64url_decode(parts[0]));
	if (!res_h.ok) {
		return Result.err(INVALID_JWT_HEADER, res_h.details);
	}
	let header = res_h.data;

	// Reject any alg outside the allow-list before touching keys (alg-confusion defence).
	let alg_allowed = false;
	for (let a in ALLOWED_ALGS) {
		if (header.alg === a) {
			alg_allowed = true;
			break;
		}
	}
	if (!alg_allowed) {
		return Result.err(UNSUPPORTED_ALGORITHM, header.alg);
	}

	let jwk_res = find_jwk(keys, header.kid);
	if (!jwk_res.ok) return jwk_res;

	let pem_res = crypto.jwk_to_pem(deps.native, jwk_res.data);
	if (!pem_res.ok) return pem_res;

	// The discovery document must describe the issuer we are configured for,
	// character for character (OIDC Discovery §4.3). discovery.discover()
	// already checked this; checking again keeps this function safe on its own.
	if (type(discovery.issuer) != "string" || discovery.issuer !== config.issuer_url) {
		return Result.err(DISCOVERY_ISSUER_MISMATCH, `Expected ${config.issuer_url}, IdP claimed ${discovery.issuer}`);
	}

	let validation_opts = {
		alg: header.alg,
		now: now,
		clock_tolerance: config.clock_tolerance,
		// OIDC Core §3.1.3.7 (2): iss must exactly match the issuer
		// identifier obtained through discovery.
		iss: discovery.issuer,
		aud: config.client_id,
		pre_parsed_header: header
	};

	let result = crypto.jwt_verify(deps.native, tokens.id_token, pem_res.data, validation_opts);
	if (!result.ok) return result;

	let payload = result.data;

	// Log claim names for debugging (Security: names only, no values)
	let claim_names = [];
	for (let k, v in payload) {
		push(claim_names, k);
	}
	deps.log("debug", `ID Token verified. Claims present: ${join(", ", claim_names)}`);

	// 3. OIDC Mandatory Claims Check. sub is a non-empty, case-sensitive
	// string (OIDC Core §2); a number, "" or null is not a subject.
	if (type(payload.sub) != "string" || length(payload.sub) == 0) {
		return Result.err(MISSING_SUB_CLAIM);
	}

	// exp and iat are REQUIRED by OIDC Core 1.0 §2.
	// These claims MUST be present for full compliance and robust token age validation.
	if (payload.exp == null) {
		return Result.err(MISSING_EXP_CLAIM);
	}
	if (payload.iat == null) {
		return Result.err(MISSING_IAT_CLAIM);
	}

	// 3.1 Nonce binds this ID token to our handshake and prevents replay.
	if (!handshake.nonce || !payload.nonce) {
		return Result.err(MISSING_NONCE);
	}
	if (!crypto.constant_time_eq(payload.nonce, handshake.nonce)) {
		return Result.err(NONCE_MISMATCH);
	}

	// 3.2 Authorized Party Check (OIDC Core §3.1.3.7 (5)): when azp is
	// present, it must be our client_id. azp is OPTIONAL (§2) and never
	// required, not even with several audiences: that rule came from errata
	// set 1 and errata set 2 removed it. An ID token with several audiences
	// is refused by the aud check anyway. "in" catches azp: "" and azp: 0,
	// which a truthiness test would let through.
	if ("azp" in payload && payload.azp !== config.client_id) {
		let got = (type(payload.azp) == "string") ? encoding.log_safe(payload.azp) : `(${type(payload.azp)})`;
		return Result.err(AZP_MISMATCH, `Expected ${config.client_id}, got ${got}`);
	}

	// 3.3 Access Token Hash Check (OIDC Core 1.0 §3.1.3.8). In the code flow
	// at_hash is OPTIONAL (§3.1.3.6), and some IdPs never send it: an ID token
	// without it is accepted. One that has it must match the access token.
	if (!tokens.access_token) {
		return Result.err(MISSING_ACCESS_TOKEN);
	}
	if (payload.at_hash != null) {
		let hash_res = crypto.hash_sha256(deps.native, tokens.access_token);
		if (!hash_res.ok) return hash_res;

		let left_half_res = encoding.binary_truncate(hash_res.data, 16);
		if (!left_half_res.ok) return Result.err(CRYPTO_ERROR);

		let expected_hash_res = encoding.b64url_encode(left_half_res.data);
		if (!expected_hash_res.ok) return Result.err(CRYPTO_ERROR);

		if (!crypto.constant_time_eq(expected_hash_res.data, payload.at_hash)) {
			return Result.err(AT_HASH_MISMATCH);
		}
	}

	let user_data = {
		sub: payload.sub,
		email: (type(payload.email) == "string") ? payload.email : null,
		// Kept as sent; config.email_is_verified decides what counts as true.
		email_verified: payload.email_verified,
		name: (type(payload.name) == "string") ? payload.name : null,
		groups: (type(payload.groups) == "array") ? payload.groups : []
	};

	return Result.ok(user_data);
};

/**
 * Fetches user claims from the UserInfo endpoint.
 *
 * The claims are returned only when the response's sub is exactly
 * expected_sub (OIDC Core §5.3.2). A response whose sub is missing, not a
 * string, empty or different fails with IDENTITY_MISMATCH (403), so no caller
 * can use claims that are not bound to the ID Token's subject.
 *
 * @param {object} deps - { http, log }
 * @param {string} endpoint - UserInfo URL
 * @param {string} access_token - OAuth2 Access Token
 * @param {string} expected_sub - The verified ID Token's sub
 * @returns {object} - Result Object {ok, data: {sub, email, ...}}
 */
export function fetch_userinfo(deps, endpoint, access_token, expected_sub) {
	if (type(expected_sub) != "string" || !length(expected_sub))
		die("CONTRACT_VIOLATION: oidc.fetch_userinfo requires the ID Token's sub");
	if (!encoding.is_https(endpoint)) return Result.err(INSECURE_USERINFO_ENDPOINT);
	if (!access_token) return Result.err(MISSING_ACCESS_TOKEN);

	deps.log("info", "Fetching supplemental claims from UserInfo endpoint");

	let res_http = deps.http.get(endpoint, {
		headers: { "Authorization": `Bearer ${access_token}` }
	});

	if (!res_http.ok) {
		deps.log("warn", `UserInfo fetch network error: ${Result.describe(res_http)}`);
		return Result.err(USERINFO_NETWORK_ERROR, { http_status: BAD_GATEWAY });
	}

	let response = res_http.data;
	if (response.status != 200) {
		deps.log("warn", `UserInfo fetch HTTP ${response.status}`);
		return Result.err(USERINFO_FETCH_FAILED, { http_status: BAD_GATEWAY });
	}

	let res = encoding.safe_json(response.body);
	if (!res.ok) {
		deps.log("error", `UserInfo JSON parse error: ${res.details}`);
		return Result.err(USERINFO_INVALID_JSON, { http_status: BAD_GATEWAY });
	}

	let payload = res.data;

	// Log claim names for debugging (Security: names only, no values)
	let claim_names = [];
	for (let k, v in payload) {
		push(claim_names, k);
	}
	deps.log("debug", `UserInfo claims received: ${join(", ", claim_names)}`);

	// The sub MUST exactly match the ID Token's sub (OIDC Core §5.3.2), or the
	// claims could belong to a different user. sub is case-sensitive, so the
	// comparison is exact. A missing, non-string or empty sub cannot match.
	let sub = (type(payload) == "object") ? payload.sub : null;
	if (type(sub) != "string" || sub !== expected_sub) {
		return Result.err(IDENTITY_MISMATCH, { http_status: FORBIDDEN });
	}

	return Result.ok(payload);
};
