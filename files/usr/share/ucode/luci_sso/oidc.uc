import * as uclient from 'uclient';
import * as lucihttp from 'lucihttp';
import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as jwk from 'luci_sso.jwk';
import * as discovery from 'luci_sso.discovery';
import * as Result from 'luci_sso.result';

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
		return Result.err("MISSING_STATE_PARAMETER");
	}
	if (!params.nonce || type(params.nonce) != "string" || length(params.nonce) < 16) {
		return Result.err("MISSING_NONCE_PARAMETER");
	}
	        	if (!params.code_challenge || type(params.code_challenge) != "string") {
	        		return Result.err("MISSING_PKCE_CHALLENGE");
	        	}
	        
	        	// BLOCKER FIX: Enforce HTTPS on authorization_endpoint (B3)
	        	if (!encoding.is_https(discovery_doc.authorization_endpoint)) {
	        		return Result.err("INSECURE_AUTH_ENDPOINT");
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

	let endpoint = discovery_doc.authorization_endpoint;
	let parts = split(endpoint, "#", 2);
	let url = parts[0];
	let fragment = (length(parts) > 1) ? "#" + parts[1] : "";

	let sep = (index(url, '?') == -1) ? '?' : '&';
	for (let k, v in query) {
		if (v == null) continue;
		url += `${sep}${k}=${lucihttp.urlencode(v, 1)}`;
		sep = '&';
	}
	return Result.ok(url + fragment);
};

/**
 * Exchanges authorization code for tokens.
 */
export function exchange_code(io, config, discovery, code, verifier, session_id) {
	if (!encoding.is_https(discovery.token_endpoint)) return Result.err("INSECURE_TOKEN_ENDPOINT");

	// Audit logging for PKCE usage (Blocker #2)
	let sid_ctx = session_id ? ` [session_id: ${session_id}]` : "";
	io.log("info", `Initiating token exchange${sid_ctx} with PKCE verifier (len: ${length(verifier)})`);

	if (type(verifier) != "string" || length(verifier) < 43 || length(verifier) > 128) {
		io.log("error", `Rejected token exchange${sid_ctx}: PKCE verifier length out of bounds`);
		return Result.err("INVALID_PKCE_VERIFIER");
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

	let response = io.http_post(discovery.token_endpoint, {
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: encoded_body,
		verify: true // Explicitly request TLS certificate verification
	});

	if (!response || response.error) {
		let err_msg = (response && response.error) ? response.error : "no response";
		io.log("warn", `Token exchange network error${sid_ctx}: ${err_msg}`);
		return Result.err("NETWORK_ERROR");
	}
	if (response.status != 200) {
		let res_err = encoding.safe_json(response.body);
		if (res_err.ok && res_err.data.error == "invalid_grant") {
			io.log("error", `Token exchange failed (invalid_grant)${sid_ctx}`);
			return Result.err("OIDC_INVALID_GRANT");
		}
		io.log("warn", `Token exchange HTTP ${response.status}${sid_ctx}`);
		return Result.err("TOKEN_EXCHANGE_FAILED", { http_status: response.status });
	}

	let res = encoding.safe_json(response.body);
	if (!res.ok) {
		io.log("error", `Token exchange JSON parse error${sid_ctx}: ${res.details}`);
		return Result.err("INVALID_JSON");
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
	if (!tokens.id_token) return Result.err("MISSING_ID_TOKEN");

	// 1. Policy Enforcement (Second Dimension)
	const DEFAULT_POLICY = { allowed_algs: ["RS256", "ES256"] };
	let p = policy || DEFAULT_POLICY;

	let parts = split(tokens.id_token, ".");
	let res_h = encoding.safe_json(crypto.b64url_decode(parts[0]));
	if (!res_h.ok) {
		return Result.err("INVALID_JWT_HEADER", res_h.details);
	}
	let header = res_h.data;

	// BLOCKER: Enforce algorithm whitelist from policy
	let alg_allowed = false;
	for (let a in p.allowed_algs) {
		if (header.alg == a) {
			alg_allowed = true;
			break;
		}
	}
	if (!alg_allowed) {
		return Result.err("UNSUPPORTED_ALGORITHM", header.alg);
	}

	let jwk_res = find_jwk(keys, header.kid);
	if (!jwk_res.ok) return jwk_res;

	let pem_res = jwk.jwk_to_pem(jwk_res.data);
	if (!pem_res.ok) return pem_res;

	// MANDATORY Claims Check
	if (!crypto.constant_time_eq(encoding.normalize_url(discovery.issuer), encoding.normalize_url(config.issuer_url))) {
		return Result.err("DISCOVERY_ISSUER_MISMATCH", `Expected ${config.issuer_url}, IdP claimed ${discovery.issuer}`);
	}

	let validation_opts = { 
		alg: header.alg,
		now: now,
		clock_tolerance: config.clock_tolerance,
		iss: config.issuer_url,
		aud: config.client_id
	};

	let result = crypto.verify_jwt(tokens.id_token, pem_res.data, validation_opts);
	if (!result.ok) return result;

	let payload = result.data;

	// Log claim names for debugging (Security: names only, no values)
	let claim_names = [];
	for (let k, v in payload) {
		push(claim_names, k);
	}
	io.log("info", `ID Token verified. Claims present: ${join(", ", claim_names)}`);

	// 3. OIDC Mandatory Claims Check
	if (!payload.sub) {
		return Result.err("MISSING_SUB_CLAIM");
	}

	// B1 & W2: Enforce mandatory exp and iat claims (OIDC Core 1.0 §2)
	// These claims MUST be present for full compliance and robust token age validation.
	if (payload.exp == null) {
		return Result.err("MISSING_EXP_CLAIM");
	}
	if (payload.iat == null) {
		return Result.err("MISSING_IAT_CLAIM");
	}

	// 3.1 Nonce Check (Blocker #3: Mandatory)
	if (!handshake.nonce || !payload.nonce) {
		return Result.err("MISSING_NONCE");
	}
	if (!crypto.constant_time_eq(payload.nonce, handshake.nonce)) {
		return Result.err("NONCE_MISMATCH");
	}

	// 3.2 Authorized Party Check
	if (type(payload.aud) == "array" && !payload.azp) {
		return Result.err("MISSING_AZP_CLAIM");
	}
	if (payload.azp && !crypto.constant_time_eq(payload.azp, config.client_id)) {
		return Result.err("AZP_MISMATCH", `Expected ${config.client_id}, got ${payload.azp}`);
	}

	// 3.3 Access Token Hash Check
	if (!tokens.access_token) {
		return Result.err("MISSING_ACCESS_TOKEN");
	}
	if (!payload.at_hash) {
		io.log("error", "ID Token missing mandatory at_hash claim (Token Binding violation)");
		return Result.err("MISSING_AT_HASH");
	}

	let full_hash = crypto.sha256(tokens.access_token);
	if (!full_hash) return Result.err("CRYPTO_ERROR");

	let left_half = encoding.binary_truncate(full_hash, 16);
	let expected_hash = crypto.b64url_encode(left_half);

	if (!crypto.constant_time_eq(expected_hash, payload.at_hash)) {
		return Result.err("AT_HASH_MISMATCH");
	}

	let user_data = {
		sub: payload.sub,
		email: payload.email,
		name: payload.name
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
	if (!encoding.is_https(endpoint)) return Result.err("INSECURE_USERINFO_ENDPOINT");
	if (!access_token) return Result.err("MISSING_ACCESS_TOKEN");

	io.log("info", "Fetching supplemental claims from UserInfo endpoint");

	let response = io.http_get(endpoint, {
		headers: { "Authorization": `Bearer ${access_token}` },
		verify: true
	});

	if (!response || response.error) {
		let err_msg = (response && response.error) ? response.error : "no response";
		io.log("warn", `UserInfo fetch network error: ${err_msg}`);
		return Result.err("NETWORK_ERROR");
	}
	if (response.status != 200) {
		io.log("warn", `UserInfo fetch HTTP ${response.status}`);
		return Result.err("USERINFO_FETCH_FAILED", { http_status: response.status });
	}

	let res = encoding.safe_json(response.body);
	if (!res.ok) {
		io.log("error", `UserInfo JSON parse error: ${res.details}`);
		return Result.err("INVALID_JSON");
	}

	let payload = res.data;

	// Log claim names for debugging (Security: names only, no values)
	let claim_names = [];
	for (let k, v in payload) {
		push(claim_names, k);
	}
	io.log("info", `UserInfo claims received: ${join(", ", claim_names)}`);

	// 1. Mandatory sub claim check (OIDC Core 1.0 §5.3.2)
	if (!payload.sub) {
		io.log("error", "UserInfo response missing mandatory 'sub' claim");
		return Result.err("MISSING_SUB_CLAIM");
	}

	return Result.ok(payload);
};
