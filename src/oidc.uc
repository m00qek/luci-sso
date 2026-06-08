import * as uclient from 'uclient';
import * as lucihttp from 'lucihttp';
import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as discovery from 'luci_sso.discovery';
import * as Result from 'luci_sso.result';
import { INSECURE_AUTH_ENDPOINT, INVALID_AUTH_ENDPOINT, MISSING_STATE_PARAMETER, MISSING_NONCE_PARAMETER, MISSING_PKCE_CHALLENGE, INSECURE_TOKEN_ENDPOINT, INVALID_PKCE_VERIFIER, TOKEN_ENDPOINT_NETWORK_ERROR, OIDC_INVALID_GRANT, TOKEN_EXCHANGE_FAILED, TOKEN_RESPONSE_INVALID_JSON, MISSING_ID_TOKEN, UNSUPPORTED_ALGORITHM, DISCOVERY_ISSUER_MISMATCH, MISSING_SUB_CLAIM, MISSING_EXP_CLAIM, MISSING_IAT_CLAIM, MISSING_NONCE, NONCE_MISMATCH, MISSING_AZP_CLAIM, AZP_MISMATCH, MISSING_ACCESS_TOKEN, MISSING_AT_HASH, AT_HASH_MISMATCH, CRYPTO_ERROR, INSECURE_USERINFO_ENDPOINT, USERINFO_FETCH_FAILED, USERINFO_NETWORK_ERROR, USERINFO_INVALID_JSON } from 'luci_sso.errors';

// --- Internal Helpers ---

// --- Public API ---

/**
 * Fetches and caches OIDC discovery document.
 */
export const discover = discovery.discover;

/**
 * Fetches JWK Set from IdP with caching.
 */
export const fetch_jwks = discovery.fetch_jwks;

/**
 * Finds the correct JWK by key ID (kid).
 */
export const find_jwk = discovery.find_jwk;

/**
 * Generates the authorization URL.
 */
export function get_auth_url(io, config, discovery_doc, params) {
	// BLOCKER FIX: Enforce mandatory CSRF protection (B1)
	if (!params.state || type(params.state) != "string" || length(params.state) < 16) {
		return Result.err(MISSING_STATE_PARAMETER);
	}

	if (!params.nonce || type(params.nonce) != "string" || length(params.nonce) < 16) {
		return Result.err(MISSING_NONCE_PARAMETER);
	}

	if (!params.code_challenge || type(params.code_challenge) != "string") {
		return Result.err(MISSING_PKCE_CHALLENGE);
	}

	// BLOCKER FIX: Enforce HTTPS on authorization_endpoint (B3)
	if (!encoding.is_https(discovery_doc.authorization_endpoint)) {
		return Result.err(INSECURE_AUTH_ENDPOINT);
	}
	
	// W2: RFC 6749 §3.1: "The endpoint URI MUST NOT include a fragment component."
	if (index(discovery_doc.authorization_endpoint, '#') != -1) {
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

	let sep = (index(url, '?') == -1) ? '?' : '&';
	for (let k, v in query) {
		if (v == null) continue;
		url += `${sep}${k}=${lucihttp.urlencode(v, 1)}`;
		sep = '&';
	}
	return Result.ok(url);
};

/**
 * Exchanges authorization code for tokens.
 */
export function exchange_code(io, config, discovery, code, verifier, session_id) {
	if (!encoding.is_https(discovery.token_endpoint)) return Result.err(INSECURE_TOKEN_ENDPOINT);

	// Audit logging for PKCE usage (Blocker #2)
	let sid_ctx = session_id ? ` [session_id: ${session_id}]` : "";
	io.log("info", `Initiating token exchange${sid_ctx}`);

	if (type(verifier) != "string" || length(verifier) < 43 || length(verifier) > 128) {
		io.log("error", `Rejected token exchange${sid_ctx}: PKCE verifier length out of bounds`);
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

	let res_http = io.http_post(discovery.token_endpoint, {
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: encoded_body
		// TLS verification is enforced by default in the IO provider
	});

	if (!res_http.ok) {
		io.log("warn", `Token exchange network error${sid_ctx}: ${res_http.error}`);
		return Result.err(TOKEN_ENDPOINT_NETWORK_ERROR);
	}

	let response = res_http.data;
	if (response.status != 200) {
		let res_err = encoding.safe_json(response.body);
		if (res_err.ok && res_err.data.error == "invalid_grant") {
			io.log("error", `Token exchange failed (invalid_grant)${sid_ctx}`);
			return Result.err(OIDC_INVALID_GRANT, { http_status: 400 });
		}
		io.log("warn", `Token exchange HTTP ${response.status}${sid_ctx}`);
		return Result.err(TOKEN_EXCHANGE_FAILED, { http_status: response.status });
	}

	let res = encoding.safe_json(response.body);
	if (!res.ok) {
		io.log("error", `Token exchange JSON parse error${sid_ctx}: ${res.details}`);
		return Result.err(TOKEN_RESPONSE_INVALID_JSON);
	}
	let tokens = res.data;

	io.log("info", `Token exchange successful${sid_ctx}`);

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
 * @param {object} [policy] - Security policy (Second Dimension) {allowed_algs}
 */
export function verify_id_token(io, tokens, keys, config, handshake, discovery, now, policy) {
	if (!tokens.id_token || type(tokens.id_token) != "string") return Result.err(MISSING_ID_TOKEN);

	// 1. Policy Enforcement (Second Dimension)
	const DEFAULT_POLICY = { allowed_algs: ["RS256", "ES256"] };
	let p = policy || DEFAULT_POLICY;

	let parts = split(tokens.id_token, ".");
	let res_h = encoding.safe_json(encoding.b64url_decode(parts[0]));
	if (!res_h.ok) {
		return Result.err("INVALID_JWT_HEADER", res_h.details);
	}
	let header = res_h.data;

	// BLOCKER: Enforce algorithm whitelist from policy
	let alg_allowed = false;
	for (let a in p.allowed_algs) {
		if (crypto.constant_time_eq(header.alg, a)) {
			alg_allowed = true;
			break;
		}
	}
	if (!alg_allowed) {
		return Result.err(UNSUPPORTED_ALGORITHM, header.alg);
	}

	let jwk_res = find_jwk(keys, header.kid);
	if (!jwk_res.ok) return jwk_res;

	let pem_res = crypto.jwk_to_pem(jwk_res.data);
	if (!pem_res.ok) return pem_res;

	// MANDATORY Claims Check
	let disc_iss_res = encoding.normalize_url(discovery.issuer);
	let conf_iss_res = encoding.normalize_url(config.issuer_url);
	if (!disc_iss_res.ok || !conf_iss_res.ok || !crypto.constant_time_eq(disc_iss_res.data, conf_iss_res.data)) {
		return Result.err(DISCOVERY_ISSUER_MISMATCH, `Expected ${config.issuer_url}, IdP claimed ${discovery.issuer}`);
	}

	let validation_opts = {
		alg: header.alg,
		now: now,
		clock_tolerance: config.clock_tolerance,
		iss: config.issuer_url,
		aud: config.client_id,
		pre_parsed_header: header
	};

	let result = crypto.jwt_verify(tokens.id_token, pem_res.data, validation_opts);
	if (!result.ok) return result;

	let payload = result.data;

	// Log claim names for debugging (Security: names only, no values)
	let claim_names = [];
	for (let k, v in payload) {
		push(claim_names, k);
	}
	io.log("debug", `ID Token verified. Claims present: ${join(", ", claim_names)}`);

	// 3. OIDC Mandatory Claims Check
	if (!payload.sub) {
		return Result.err(MISSING_SUB_CLAIM);
	}

	// B1 & W2: Enforce mandatory exp and iat claims (OIDC Core 1.0 §2)
	// These claims MUST be present for full compliance and robust token age validation.
	if (payload.exp == null) {
		return Result.err(MISSING_EXP_CLAIM);
	}
	if (payload.iat == null) {
		return Result.err(MISSING_IAT_CLAIM);
	}

	// 3.1 Nonce Check (Blocker #3: Mandatory)
	if (!handshake.nonce || !payload.nonce) {
		return Result.err(MISSING_NONCE);
	}
	if (!crypto.constant_time_eq(payload.nonce, handshake.nonce)) {
		return Result.err(NONCE_MISMATCH);
	}

	// 3.2 Authorized Party Check (OIDC Core 1.0 §3.1.3.7 items 4-5)
	// azp is required only when the ID Token has MULTIPLE audiences.
	if (type(payload.aud) == "array" && length(payload.aud) > 1 && !payload.azp) {
		return Result.err(MISSING_AZP_CLAIM);
	}
	if (payload.azp && !crypto.constant_time_eq(payload.azp, config.client_id)) {
		return Result.err(AZP_MISMATCH, `Expected ${config.client_id}, got ${payload.azp}`);
	}

	// 3.3 Access Token Hash Check
	if (!tokens.access_token) {
		return Result.err(MISSING_ACCESS_TOKEN);
	}
	if (!payload.at_hash) {
		io.log("error", "ID Token missing mandatory at_hash claim (Token Binding violation)");
		return Result.err(MISSING_AT_HASH);
	}

	let hash_res = crypto.hash_sha256(tokens.access_token);
	if (!hash_res.ok) return hash_res;
	let full_hash = hash_res.data;

	let left_half_res = encoding.binary_truncate(full_hash, 16);
	if (!left_half_res.ok) return Result.err(CRYPTO_ERROR);

	let expected_hash_res = encoding.b64url_encode(left_half_res.data);
	if (!expected_hash_res.ok) return Result.err(CRYPTO_ERROR);

	if (!crypto.constant_time_eq(expected_hash_res.data, payload.at_hash)) {
		return Result.err(AT_HASH_MISMATCH);
	}

	let user_data = {
		sub: payload.sub,
		email: (type(payload.email) == "string") ? payload.email : null,
		name: (type(payload.name) == "string") ? payload.name : null,
		groups: (type(payload.groups) == "array") ? payload.groups : []
	};

	return Result.ok(user_data);
};

/**
 * Fetches user claims from the UserInfo endpoint.
 * 
 * @param {object} io - I/O provider
 * @param {string} endpoint - UserInfo URL
 * @param {string} access_token - OAuth2 Access Token
 * @returns {object} - Result Object {ok, data: {sub, email, ...}}
 */
export function fetch_userinfo(io, endpoint, access_token) {
	if (!encoding.is_https(endpoint)) return Result.err(INSECURE_USERINFO_ENDPOINT);
	if (!access_token) return Result.err(MISSING_ACCESS_TOKEN);

	io.log("info", "Fetching supplemental claims from UserInfo endpoint");

	let res_http = io.http_get(endpoint, {
		headers: { "Authorization": `Bearer ${access_token}` }
		// TLS verification is enforced by default in the IO provider
	});

	if (!res_http.ok) {
		io.log("warn", `UserInfo fetch network error: ${res_http.error}`);
		return Result.err(USERINFO_NETWORK_ERROR);
	}

	let response = res_http.data;
	if (response.status != 200) {
		io.log("warn", `UserInfo fetch HTTP ${response.status}`);
		return Result.err(USERINFO_FETCH_FAILED, { http_status: response.status });
	}

	let res = encoding.safe_json(response.body);
	if (!res.ok) {
		io.log("error", `UserInfo JSON parse error: ${res.details}`);
		return Result.err(USERINFO_INVALID_JSON);
	}

	let payload = res.data;

	// Log claim names for debugging (Security: names only, no values)
	let claim_names = [];
	for (let k, v in payload) {
		push(claim_names, k);
	}
	io.log("debug", `UserInfo claims received: ${join(", ", claim_names)}`);

	// 1. Mandatory sub claim check (OIDC Core 1.0 §5.3.2)
	if (!payload.sub) {
		io.log("error", "UserInfo response missing mandatory 'sub' claim");
		return Result.err(MISSING_SUB_CLAIM);
	}

	return Result.ok(payload);
};
