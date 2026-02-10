import * as uclient from 'uclient';
import * as lucihttp from 'lucihttp';
import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as jwk from 'luci_sso.jwk';
import * as discovery from 'luci_sso.discovery';

// --- Internal Helpers ---

/**
 * Checks if a URL uses HTTPS.
 * @private
 */
function _is_https(url) {
	return (type(url) == "string" && substr(url, 0, 8) == "https://");
}

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
	return url;
};

/**
 * Exchanges authorization code for tokens.
 */
export function exchange_code(io, config, discovery, code, verifier, session_id) {
	if (!_is_https(discovery.token_endpoint)) return { ok: false, error: "INSECURE_TOKEN_ENDPOINT" };

	// Audit logging for PKCE usage (Blocker #2)
	let sid_ctx = session_id ? ` [session_id: ${session_id}]` : "";
	io.log("info", `Initiating token exchange${sid_ctx} with PKCE verifier (len: ${length(verifier)})`);

	if (type(verifier) != "string" || length(verifier) < 43) {
		io.log("error", `Rejected token exchange${sid_ctx}: PKCE verifier too short`);
		return { ok: false, error: "INVALID_PKCE_VERIFIER" };
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
		io.log("warn", `Token exchange network error${sid_ctx}: ${response?.error || "no response"}`);
		return { ok: false, error: "NETWORK_ERROR" };
	}
	if (response.status != 200) {
		let res_err = encoding.safe_json(response.body);
		if (res_err.ok && res_err.data.error == "invalid_grant") {
			io.log("error", `Token exchange failed (invalid_grant)${sid_ctx}`);
			return { ok: false, error: "OIDC_INVALID_GRANT" };
		}
		io.log("warn", `Token exchange HTTP ${response.status}${sid_ctx}`);
		return { ok: false, error: "TOKEN_EXCHANGE_FAILED", details: response.status };
	}

	let res = encoding.safe_json(response.body);
	if (!res.ok) {
		io.log("error", `Token exchange JSON parse error${sid_ctx}: ${res.details}`);
		return { ok: false, error: "INVALID_JSON" };
	}
	let tokens = res.data;

	io.log("info", `Token exchange successful${sid_ctx}`);

	return { ok: true, data: tokens };
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
export function verify_id_token(tokens, keys, config, handshake, discovery, now, policy) {
	if (!tokens.id_token) return { ok: false, error: "MISSING_ID_TOKEN" };

	// 1. Policy Enforcement (Second Dimension)
	const DEFAULT_POLICY = { allowed_algs: ["RS256", "ES256"] };
	let p = policy || DEFAULT_POLICY;

	let parts = split(tokens.id_token, ".");
	let res_h = encoding.safe_json(crypto.b64url_decode(parts[0]));
	if (!res_h.ok) {
		return { ok: false, error: "INVALID_JWT_HEADER", details: res_h.details };
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
		return { ok: false, error: "UNSUPPORTED_ALGORITHM", details: header.alg };
	}

	let jwk_res = find_jwk(keys, header.kid);
	if (!jwk_res.ok) return jwk_res;

	let pem_res = jwk.jwk_to_pem(jwk_res.data);
	if (!pem_res.ok) return pem_res;

	// MANDATORY Claims Check
	if (discovery.issuer != config.issuer_url) {
		return { 
			ok: false, 
			error: "DISCOVERY_ISSUER_MISMATCH", 
			details: `Expected ${config.issuer_url}, IdP claimed ${discovery.issuer}` 
		};
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

	// 3. OIDC Mandatory Claims Check
	if (!payload.sub) {
		return { ok: false, error: "MISSING_SUB_CLAIM" };
	}

	// 3.1 Nonce Check (Blocker #3: Mandatory)
	if (!handshake.nonce || !payload.nonce) {
		return { ok: false, error: "MISSING_NONCE" };
	}
	if (!crypto.constant_time_eq(payload.nonce, handshake.nonce)) {
		return { ok: false, error: "NONCE_MISMATCH" };
	}

	// 3.2 Authorized Party Check
	if (payload.azp && payload.azp !== config.client_id) {
		return { ok: false, error: "AZP_MISMATCH", details: `Expected ${config.client_id}, got ${payload.azp}` };
	}

	// 3.3 Access Token Hash Check
	if (!tokens.access_token) {
		return { ok: false, error: "MISSING_ACCESS_TOKEN" };
	}
	if (!payload.at_hash) {
		return { ok: false, error: "MISSING_AT_HASH" };
	}

	let full_hash = crypto.sha256(tokens.access_token);
	if (!full_hash) return { ok: false, error: "CRYPTO_ERROR" };

	let left_half = encoding.binary_truncate(full_hash, 16);
	let expected_hash = crypto.b64url_encode(left_half);

	if (!crypto.constant_time_eq(expected_hash, payload.at_hash)) {
		return { ok: false, error: "AT_HASH_MISMATCH" };
	}

	let user_data = {
		sub: payload.sub,
		email: payload.email || payload.sub,
		name: payload.name
	};

	return { ok: true, data: user_data };
};
