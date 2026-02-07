import * as native from 'luci_sso.native';

const MAX_TOKEN_SIZE = 16384; // 16 KB
const MAX_UTILS_SIZE = 32768; // 32 KB

// --- Base64URL Internal Helpers ---

/**
 * Maps standard Base64 characters to URL-safe ones.
 * @private
 */
function _map_to_url_safe(str) {
	let res = replace(str, /\+/g, '-');
	return replace(res, /\//g, '_');
}

/**
 * Maps URL-safe characters back to standard Base64.
 * @private
 */
function _map_from_url_safe(str) {
	let res = replace(str, /-/g, '+');
	return replace(res, /_/g, '/');
}

/**
 * Adds padding characters to a Base64 string if needed.
 * @private
 */
function _add_padding(str) {
	let pad = (4 - (length(str) % 4)) % 4;
	for (let i = 0; i < pad; i++) {
		str += '=';
	}
	return str;
}

/**
 * Removes all padding characters from a Base64 string.
 * @private
 */
function _strip_padding(str) {
	return replace(str, /=/g, '');
}

/**
 * Converts Base64URL to Standard Base64 with padding.
 * Internal helper for decoding operations.
 * @private
 */
function b64url_to_b64(str) {
	if (type(str) != "string") return null;
	if (length(str) == 0) return "";
	
	// Validate Base64URL charset: [A-Za-z0-9_-]
	if (!match(str, /^[A-Za-z0-9_-]+$/)) return null;
	
	return _add_padding(_map_from_url_safe(str));
}

// --- JSON Helpers ---

/**
 * Decodes JSON safely.
 * @private
 */
function safe_json(str) {
	try {
		return json(str);
	} catch (e) {
		return null;
	}
}

// --- String Comparison ---

/**
 * Constant-time string comparison to prevent timing attacks.
 * @private
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
}

// --- Public API ---

/**
 * Decodes a Base64URL string to a raw string.
 * Enforces a strict size limit to prevent OOM.
 * 
 * @param {string} str - Base64URL string
 * @returns {string} - Raw binary string or null
 */
export function b64url_decode(str) {
	if (type(str) != "string") die("CONTRACT_VIOLATION: b64url_decode expects string");
	
	if (length(str) > MAX_UTILS_SIZE) return null;

	let b64 = b64url_to_b64(str);
	return (b64 != null) ? b64dec(b64) : null;
};

/**
 * Encodes a raw string to Base64URL.
 * 
 * @param {string} str - Raw binary string
 * @returns {string} - Base64URL string
 */
export function b64url_encode(str) {
	if (type(str) != "string") die("CONTRACT_VIOLATION: b64url_encode expects string");
	
	let b64 = b64enc(str);
	return _strip_padding(_map_to_url_safe(b64));
};

/**
 * Signs a payload using HMAC-SHA256 and returns a JWS (Compact Serialization).
 * 
 * @param {object} payload - Data to sign
 * @param {string} secret - Binary secret key
 * @returns {string} - Compact JWS string
 */
export function sign_jws(payload, secret) {
	if (type(payload) != "object") die("CONTRACT_VIOLATION: sign_jws expects object payload");
	if (type(secret) != "string") die("CONTRACT_VIOLATION: sign_jws expects string secret");
	
	let header = { alg: "HS256", typ: "JWT" };
	let b64_header = b64url_encode(sprintf("%J", header));
	let b64_payload = b64url_encode(sprintf("%J", payload));
	let signed_data = b64_header + "." + b64_payload;
	
	let signature = native.hmac_sha256(secret, signed_data);
	if (!signature) die("CRYPTO_ERROR: hmac_sha256 failed");

	return signed_data + "." + b64url_encode(signature);
};

/**
 * Verifies a JWS (HMAC-SHA256) and returns the parsed payload if valid.
 * 
 * @param {string} token - Compact JWS string
 * @param {string} secret - Binary secret key
 * @returns {object} - Result Object {ok, data/error}
 */
export function verify_jws(token, secret) {
	if (type(token) != "string") die("CONTRACT_VIOLATION: verify_jws expects string token");
	if (type(secret) != "string") die("CONTRACT_VIOLATION: verify_jws expects string secret");

	if (length(token) > MAX_TOKEN_SIZE) return { ok: false, error: "TOKEN_TOO_LARGE" };
	
	let parts = split(token, ".", 4);
	if (length(parts) != 3) return { ok: false, error: "MALFORMED_JWS" };

	// 1. Decode and Validate Header
	let header_json = b64url_decode(parts[0]);
	if (!header_json) return { ok: false, error: "INVALID_HEADER_ENCODING" };
	let header = safe_json(header_json);
	if (!header || header.alg != "HS256") {
		return { ok: false, error: "UNSUPPORTED_ALGORITHM", details: header ? header.alg : "missing" };
	}

	// 2. Verify Signature
	let signed_data = parts[0] + "." + parts[1];
	let provided_sig = b64url_decode(parts[2]);
	if (!provided_sig) return { ok: false, error: "INVALID_SIGNATURE_ENCODING" };
	
	let calculated_sig = native.hmac_sha256(secret, signed_data);
	if (!calculated_sig || !constant_time_eq(calculated_sig, provided_sig)) {
		return { ok: false, error: "INVALID_SIGNATURE" };
	}
	
	// 3. Decode Payload
	let payload_json = b64url_decode(parts[1]);
	if (!payload_json) return { ok: false, error: "INVALID_PAYLOAD_ENCODING" };
	let payload = safe_json(payload_json);
	if (!payload) return { ok: false, error: "INVALID_PAYLOAD_JSON" };

	return { ok: true, data: payload };
};

/**
 * Parses and validates an OIDC JWT (Public Key: RS256/ES256).
 * 
 * @param {string} token - JWT string
 * @param {string} pubkey - PEM public key
 * @param {object} options - Validation options {alg, iss, aud, skew}
 * @returns {object} - Result Object {ok, data/error}
 */
export function verify_jwt(token, pubkey, options) {
	if (type(token) != "string") die("CONTRACT_VIOLATION: verify_jwt expects string token");
	if (type(pubkey) != "string") die("CONTRACT_VIOLATION: verify_jwt expects string pubkey");
	if (type(options) != "object") die("CONTRACT_VIOLATION: verify_jwt expects object options");
	if (type(options.now) != "int") die("CONTRACT_VIOLATION: verify_jwt expects mandatory integer options.now");
	if (type(options.clock_tolerance) != "int") die("CONTRACT_VIOLATION: verify_jwt expects mandatory integer options.clock_tolerance");

	if (length(token) > MAX_TOKEN_SIZE) return { ok: false, error: "TOKEN_TOO_LARGE" };
	if (!options.alg) return { ok: false, error: "MISSING_ALGORITHM_OPTION" };

	let parts = split(token, ".", 4);
	if (length(parts) != 3) return { ok: false, error: "MALFORMED_JWT" };

	// 1. Decode and Validate Header
	let header_json = b64url_decode(parts[0]);
	if (!header_json) return { ok: false, error: "INVALID_HEADER_ENCODING" };
	let header = safe_json(header_json);
	if (!header || !header.alg) return { ok: false, error: "INVALID_HEADER_JSON" };

	// 2. Decode and Validate Payload Encoding (Fail Fast)
	let payload_json = b64url_decode(parts[1]);
	if (!payload_json) return { ok: false, error: "INVALID_PAYLOAD_ENCODING" };

	// 3. Algorithm Enforcement
	if (header.alg != options.alg) {
		return { ok: false, error: "ALGORITHM_MISMATCH", details: `Expected ${options.alg}, got ${header.alg}` };
	}

	// 4. Decode and Verify Signature
	let signature = b64url_decode(parts[2]);
	if (!signature) return { ok: false, error: "INVALID_SIGNATURE_ENCODING" };

	let signed_data = parts[0] + "." + parts[1];
	let valid = false;

	if (options.alg == "RS256") {
		valid = native.verify_rs256(signed_data, signature, pubkey);
	} else if (options.alg == "ES256") {
		valid = native.verify_es256(signed_data, signature, pubkey);
	} else if (options.alg == "HS256") {
		// For HS256, pubkey is actually the binary secret
		let calculated = native.hmac_sha256(pubkey, signed_data);
		valid = calculated && constant_time_eq(calculated, signature);
	} else {
		return { ok: false, error: "UNSUPPORTED_ALGORITHM" };
	}

	if (!valid) return { ok: false, error: "INVALID_SIGNATURE" };

	// 5. Decode Payload JSON
	let payload = safe_json(payload_json);
	if (!payload) return { ok: false, error: "INVALID_PAYLOAD_JSON" };

	// 6. Claims Validation
	let clock_tolerance = options.clock_tolerance;
	let now = options.now;

	if (payload.exp && payload.exp < (now - clock_tolerance)) {
		return { ok: false, error: "TOKEN_EXPIRED" };
	}
	
	if (payload.nbf && payload.nbf > (now + clock_tolerance)) {
		return { ok: false, error: "TOKEN_NOT_YET_VALID" };
	}

	if (payload.iat && payload.iat > (now + clock_tolerance)) {
		return { ok: false, error: "TOKEN_ISSUED_IN_FUTURE" };
	}

	if (options.iss && payload.iss !== options.iss) {
		return { ok: false, error: "ISSUER_MISMATCH" };
	}

	if (options.aud) {
		let aud = payload.aud;
		let found = false;
		if (type(aud) == "array") {
			if (length(aud) == 0) return { ok: false, error: "INVALID_AUDIENCE" };
			for (let a in aud) {
				if (type(a) != "string") return { ok: false, error: "MALFORMED_AUDIENCE" };
				if (a === options.aud) {
					found = true;
					break;
				}
			}
		} else {
			found = (aud === options.aud);
		}
		
		if (!found) {
			return { ok: false, error: "AUDIENCE_MISMATCH" };
		}
	}

	return { ok: true, data: payload };
};

/**
 * Generates cryptographically secure random bytes.
 * 
 * @param {number} [len=32] - Number of bytes to generate
 * @returns {string} - Random binary string
 */
export function random(len) {
	if (type(len) != "int" && len != null) die("CONTRACT_VIOLATION: random expects integer length");
	return native.random(len || 32);
};

/**
 * Calculates SHA256 hash.
 * 
 * @param {string} str - Data to hash
 * @returns {string} - 32-byte binary hash string
 */
export function sha256(str) {
	if (type(str) != "string") die("CONTRACT_VIOLATION: sha256 expects string input");
	return native.sha256(str);
};

/**
 * Generates a PKCE Code Verifier.
 * 
 * @param {number} [len=43] - Length of verifier
 * @returns {string} - Base64URL encoded verifier
 */
export function pkce_generate_verifier(len) {
	let byte_len = len || 43;
	if (byte_len < 32 || byte_len > 96) die("CONTRACT_VIOLATION: PKCE verifier must be 32-96 bytes");
	
	let bytes = random(byte_len);
	return b64url_encode(bytes);
};

/**
 * Calculates a PKCE Code Challenge from a verifier using S256.
 * 
 * @param {string} verifier - PKCE verifier string
 * @returns {string} - Base64URL encoded challenge
 */
export function pkce_calculate_challenge(verifier) {
	let hash = sha256(verifier);
	return b64url_encode(hash);
};

/**
 * Generates a PKCE Verifier and Challenge pair.
 * 
 * @param {number} [len] - Optional verifier length
 * @returns {object} - {verifier, challenge}
 */
export function pkce_pair(len) {
	let verifier = pkce_generate_verifier(len);
	let challenge = pkce_calculate_challenge(verifier);
	return { verifier, challenge };
};

/**
 * Converts a JWK object to a PEM string.
 * 
 * @param {object} jwk - JWK object
 * @returns {object} - Result Object {ok, data/error}
 */
export function jwk_to_pem(jwk) {
	if (!jwk || type(jwk) != "object") die("CONTRACT_VIOLATION: jwk_to_pem expects object jwk");
	if (!jwk.kty) return { ok: false, error: "MISSING_KTY" };

	if (jwk.kty == "RSA") {
		if (!jwk.n || !jwk.e) return { ok: false, error: "MISSING_RSA_PARAMS" };
		let n_bin = b64url_decode(jwk.n);
		let e_bin = b64url_decode(jwk.e);
		if (!n_bin || !e_bin) return { ok: false, error: "INVALID_RSA_PARAMS_ENCODING" };
		
		let pem = native.jwk_rsa_to_pem(n_bin, e_bin);
		if (!pem) return { ok: false, error: "PEM_CONVERSION_FAILED" };
		return { ok: true, data: pem };
		
	} else if (jwk.kty == "EC") {
		if (jwk.crv != "P-256") return { ok: false, error: "UNSUPPORTED_CURVE" };
		if (!jwk.x || !jwk.y) return { ok: false, error: "MISSING_EC_PARAMS" };
		
		let x_bin = b64url_decode(jwk.x);
		let y_bin = b64url_decode(jwk.y);
		if (!x_bin || !y_bin) return { ok: false, error: "INVALID_EC_PARAMS_ENCODING" };
		
		let pem = native.jwk_ec_p256_to_pem(x_bin, y_bin);
		if (!pem) return { ok: false, error: "PEM_CONVERSION_FAILED" };
		return { ok: true, data: pem };
	} else if (jwk.kty == "oct") {
		if (!jwk.k) return { ok: false, error: "MISSING_OCT_PARAM" };
		let k_bin = b64url_decode(jwk.k);
		if (!k_bin) return { ok: false, error: "INVALID_OCT_PARAM_ENCODING" };
		return { ok: true, data: k_bin };
	}
	
	return { ok: false, error: "UNSUPPORTED_KTY" };
};