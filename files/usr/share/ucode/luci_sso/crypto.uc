import * as native from 'luci_sso.native';

const MAX_TOKEN_SIZE = 16384; // 16 KB

/**
 * Converts Base64URL to Standard Base64 and adds padding.
 */
function b64url_to_b64(str) {
	if (type(str) != "string") return null;
	if (length(str) == 0) return "";
	
	// Validate Base64URL charset: [A-Za-z0-9_-]
	if (!match(str, /^[A-Za-z0-9_-]+$/)) return null;
	
	let b64 = replace(str, /-/g, '+');
	b64 = replace(b64, /_/g, '/');
	
	let pad = (4 - (length(b64) % 4)) % 4;
	for (let i = 0; i < pad; i++) {
		b64 += '=';
	}
	
	return b64;
}

function safe_json(str) {
	try {
		return json(str);
	} catch (e) {
		return null;
	}
}

/**
 * Decodes a Base64URL string to a raw string.
 */
export function b64url_decode(str) {
	let b64 = b64url_to_b64(str);
	return (b64 != null) ? b64dec(b64) : null;
};

/**
 * Encodes a raw string to Base64URL.
 */
export function b64url_encode(str) {
	let b64 = b64enc(str);
	b64 = replace(b64, /\+/g, '-');
	b64 = replace(b64, /\//g, '_');
	b64 = replace(b64, /=/g, '');
	return b64;
};

/**
 * Signs a payload using HMAC-SHA256 and returns a JWS (Compact Serialization).
 */
export function sign_jws(payload, secret) {
	if (type(payload) != "object") return null;
	
	let header = { alg: "HS256", typ: "JWT" };
	let b64_header = b64url_encode(sprintf("%J", header));
	let b64_payload = b64url_encode(sprintf("%J", payload));
	let signed_data = b64_header + "." + b64_payload;
	
	let signature = native.hmac_sha256(secret, signed_data);
	if (!signature) return null;

	return signed_data + "." + b64url_encode(signature);
};

/**
 * Constant-time string comparison to prevent timing attacks.
 */
function constant_time_eq(a, b) {
	if (type(a) != "string" || type(b) != "string") return false;
	let len_a = length(a);
	if (len_a != length(b)) return false;

	let res = 0;
	for (let i = 0; i < len_a; i++) {
		res |= (ord(a, i) ^ ord(b, i));
	}
	return (res == 0);
};

/**
 * Verifies a JWS (HMAC-SHA256) and returns the parsed payload if valid.
 */
export function verify_jws(token, secret) {
	if (type(token) != "string") return { error: "TOKEN_NOT_STRING" };
	if (length(token) > MAX_TOKEN_SIZE) return { error: "TOKEN_TOO_LARGE" };
	
	let parts = split(token, ".");
	if (length(parts) != 3) return { error: "MALFORMED_JWS" };

	// 1. Decode and Validate Header
	let header_json = b64url_decode(parts[0]);
	if (!header_json) return { error: "INVALID_HEADER_ENCODING" };
	let header = safe_json(header_json);
	if (!header || header.alg != "HS256") {
		return { error: "UNSUPPORTED_ALGORITHM", details: header ? header.alg : "missing" };
	}

	// 2. Verify Signature
	let signed_data = parts[0] + "." + parts[1];
	let provided_sig = b64url_decode(parts[2]);
	if (!provided_sig) return { error: "INVALID_SIGNATURE_ENCODING" };
	
	let calculated_sig = native.hmac_sha256(secret, signed_data);
	if (!calculated_sig || !constant_time_eq(calculated_sig, provided_sig)) {
		return { error: "INVALID_SIGNATURE" };
	}
	
	// 3. Decode Payload
	let payload_json = b64url_decode(parts[1]);
	if (!payload_json) return { error: "INVALID_PAYLOAD_ENCODING" };
	let payload = safe_json(payload_json);
	if (!payload) return { error: "INVALID_PAYLOAD_JSON" };

	return { payload: payload };
};

/**
 * Parses and validates an OIDC JWT (Public Key: RS256/ES256).
 */
export function verify_jwt(token, pubkey, options) {
	if (type(token) != "string") return { error: "TOKEN_NOT_STRING" };
	if (length(token) > MAX_TOKEN_SIZE) return { error: "TOKEN_TOO_LARGE" };
	if (!options || !options.alg) return { error: "MISSING_ALGORITHM_OPTION" };

	let parts = split(token, ".");
	if (length(parts) != 3) return { error: "MALFORMED_JWT" };

	// 1. Decode Header
	let header_b64 = b64url_to_b64(parts[0]);
	let header_json = b64dec(header_b64);
	if (!header_json) return { error: "INVALID_HEADER_ENCODING" };
	
	let header = safe_json(header_json);
	if (!header || !header.alg) return { error: "INVALID_HEADER_JSON" };

	// 2. Algorithm Enforcement
	if (header.alg != options.alg) {
		return { error: "ALGORITHM_MISMATCH", details: `Expected ${options.alg}, got ${header.alg}` };
	}

	// 3. Decode Signature
	let sig_b64 = b64url_to_b64(parts[2]);
	let signature = b64dec(sig_b64);
	if (!signature) return { error: "INVALID_SIGNATURE_ENCODING" };

	// 4. Verify Signature
	let signed_data = parts[0] + "." + parts[1];
	let valid = false;

	if (options.alg == "RS256") {
		valid = native.verify_rs256(signed_data, signature, pubkey);
	} else if (options.alg == "ES256") {
		valid = native.verify_es256(signed_data, signature, pubkey);
	} else {
		return { error: "UNSUPPORTED_ALGORITHM" };
	}

	if (!valid) return { error: "INVALID_SIGNATURE" };

	// 5. Decode Payload
	let payload_b64 = b64url_to_b64(parts[1]);
	let payload_json = b64dec(payload_b64);
	if (!payload_json) return { error: "INVALID_PAYLOAD_ENCODING" };

	let payload = safe_json(payload_json);
	if (!payload) return { error: "INVALID_PAYLOAD_JSON" };

	// 6. Claims Validation
	let skew = options.skew || 300; // Default 5 minutes
	let now = time();

	if (payload.exp && payload.exp < (now - skew)) {
		return { error: "TOKEN_EXPIRED" };
	}
	
	if (payload.nbf && payload.nbf > (now + skew)) {
		return { error: "TOKEN_NOT_YET_VALID" };
	}

	if (options.iss && payload.iss != options.iss) {
		return { error: "ISSUER_MISMATCH" };
	}

	if (options.aud && payload.aud != options.aud) {
		return { error: "AUDIENCE_MISMATCH" };
	}

	return { payload: payload };
};

/**
 * Generates cryptographically secure random bytes.
 */
export function random(len) {
	return native.random(len);
};

/**
 * Generates a PKCE Code Verifier.
 */
export function pkce_generate_verifier(len) {
	let bytes = native.random(len || 43);
	return b64url_encode(bytes);
};

/**
 * Calculates a PKCE Code Challenge from a verifier using S256.
 */
export function pkce_calculate_challenge(verifier) {
	let hash = native.sha256(verifier);
	return b64url_encode(hash);
};

/**
 * Generates a PKCE Verifier and Challenge pair.
 */
export function pkce_pair(len) {
	let verifier = pkce_generate_verifier(len);
	let challenge = pkce_calculate_challenge(verifier);
	return { verifier, challenge };
};

/**
 * Converts a JWK object to a PEM string.
 */
export function jwk_to_pem(jwk) {
	if (!jwk || type(jwk) != "object") return { error: "INVALID_JWK_OBJECT" };
	if (!jwk.kty) return { error: "MISSING_KTY" };

	if (jwk.kty == "RSA") {
		if (!jwk.n || !jwk.e) return { error: "MISSING_RSA_PARAMS" };
		let n_bin = b64url_decode(jwk.n);
		let e_bin = b64url_decode(jwk.e);
		if (!n_bin || !e_bin) return { error: "INVALID_RSA_PARAMS_ENCODING" };
		
		let pem = native.jwk_rsa_to_pem(n_bin, e_bin);
		if (!pem) return { error: "PEM_CONVERSION_FAILED" };
		return { pem: pem };
		
	} else if (jwk.kty == "EC") {
		if (jwk.crv != "P-256") return { error: "UNSUPPORTED_CURVE" };
		if (!jwk.x || !jwk.y) return { error: "MISSING_EC_PARAMS" };
		
		let x_bin = b64url_decode(jwk.x);
		let y_bin = b64url_decode(jwk.y);
		if (!x_bin || !y_bin) return { error: "INVALID_EC_PARAMS_ENCODING" };
		
		let pem = native.jwk_ec_p256_to_pem(x_bin, y_bin);
		if (!pem) return { error: "PEM_CONVERSION_FAILED" };
		return { pem: pem };
	}
	
	return { error: "UNSUPPORTED_KTY" };
};