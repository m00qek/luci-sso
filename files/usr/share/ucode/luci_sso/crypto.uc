import * as native from 'luci_sso.native';
import * as encoding from 'luci_sso.encoding';
import * as jwk from 'luci_sso.jwk';
import * as Result from 'luci_sso.result';

const MAX_TOKEN_SIZE = 16384; // 16 KB

// --- JSON Helpers ---

/**
 * Decodes JSON safely using the pure encoding module.
 */
export const safe_json = encoding.safe_json;

// --- String Comparison ---

/**
 * Constant-time string comparison to prevent timing attacks.
 * 
 * This implementation avoids early returns on length mismatch or content
 * difference to mitigate timing side-channels.
 * 
 * NOTE: True constant-time execution is impossible in an interpreted runtime 
 * like ucode due to GC, hash-table-backed strings, and variable-time ord().
 * This function provides a best-effort mitigation by using the XOR-accumulator 
 * pattern and avoiding logical branching based on secret content.
 */
export function constant_time_eq(a, b) {
	if (type(a) != "string" || type(b) != "string") return false;

	let len_a = length(a);
	let len_b = length(b);

	// MANDATORY: Length cap to prevent DoS via amplification (W1)
	// Any value longer than 16KB is considered excessive for tokens/hashes in this system.
	if (len_a > 16384 || len_b > 16384) return false;

	let res = (len_a ^ len_b);

	// We iterate based on the length of the first string (usually the untrusted input).
	// This ensures that for a given input length, the execution time is constant
	// regardless of the secret's content or length.
	for (let i = 0; i < len_a; i++) {
		let char_a = ord(a, i);
		let char_b = ord(b, i % (len_b || 1));
		res |= (char_a ^ char_b);
	}

	return (res == 0);
};

// --- Public API ---

/**
 * Encodes a raw string to Base64URL.
 */
export const b64url_encode = encoding.b64url_encode;

/**
 * Decodes a Base64URL string to a raw string.
 */
export const b64url_decode = encoding.b64url_decode;

/**
 * Signs a payload using HMAC-SHA256 and returns a JWS (Compact Serialization).
 * 
 * @param {object} payload - Data to sign
 * @param {string} secret - Binary secret key
 * @returns {object} - Result Object {ok, data/error}
 */
export function sign_jws(payload, secret) {
	if (type(payload) != "object") die("CONTRACT_VIOLATION: sign_jws expects object payload");
	if (type(secret) != "string") die("CONTRACT_VIOLATION: sign_jws expects string secret");

	let header = { alg: "HS256", typ: "JWT" };
	let b64_header = b64url_encode(sprintf("%J", header));
	let b64_payload = b64url_encode(sprintf("%J", payload));
	let signed_data = b64_header + "." + b64_payload;

	let signature = native.hmac_sha256(secret, signed_data);
	if (!signature) return Result.err("CRYPTO_ERROR", "hmac_sha256 failed");

	return Result.ok(signed_data + "." + b64url_encode(signature));
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

	if (length(token) > MAX_TOKEN_SIZE) return Result.err("TOKEN_TOO_LARGE");

	let parts = split(token, ".", 4);
	if (length(parts) != 3) return Result.err("MALFORMED_JWS");

	// 1. Decode and Validate Header
	let header_json = b64url_decode(parts[0]);
	if (!header_json) return Result.err("INVALID_HEADER_ENCODING");
	let res_h = safe_json(header_json);
	if (!res_h.ok) return Result.err("INVALID_HEADER_JSON");
	let header = res_h.data;
	if (header.alg != "HS256") {
		return Result.err("UNSUPPORTED_ALGORITHM", header.alg);
	}

	// 2. Verify Signature
	let signed_data = parts[0] + "." + parts[1];
	let provided_sig = b64url_decode(parts[2]);
	if (!provided_sig) return Result.err("INVALID_SIGNATURE_ENCODING");

	let calculated_sig = native.hmac_sha256(secret, signed_data);
	if (!calculated_sig || !constant_time_eq(calculated_sig, provided_sig)) {
		return Result.err("INVALID_SIGNATURE");
	}

	// 3. Decode Payload
	let payload_json = b64url_decode(parts[1]);
	if (!payload_json) return Result.err("INVALID_PAYLOAD_ENCODING");
	let res_p = safe_json(payload_json);
	if (!res_p.ok) return Result.err("INVALID_PAYLOAD_JSON");
	let payload = res_p.data;

	return Result.ok(payload);
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

	if (length(token) > MAX_TOKEN_SIZE) return Result.err("TOKEN_TOO_LARGE");
	if (!options.alg) return Result.err("MISSING_ALGORITHM_OPTION");

	let parts = split(token, ".", 4);
	if (length(parts) != 3) return Result.err("MALFORMED_JWT");

	// 1. Decode and Validate Header
	let header_json = b64url_decode(parts[0]);
	if (!header_json) return Result.err("INVALID_HEADER_ENCODING");
	let res_h = safe_json(header_json);
	if (!res_h.ok || !res_h.data.alg) return Result.err("INVALID_HEADER_JSON");
	let header = res_h.data;

	// 2. Decode and Validate Payload Encoding (Fail Fast)
	let payload_json = b64url_decode(parts[1]);
	if (!payload_json) return Result.err("INVALID_PAYLOAD_ENCODING");

	// 3. Algorithm Enforcement
	if (header.alg != options.alg) {
		return Result.err("ALGORITHM_MISMATCH", `Expected ${options.alg}, got ${header.alg}`);
	}

	// 4. Decode and Verify Signature
	let signature = b64url_decode(parts[2]);
	if (!signature) return Result.err("INVALID_SIGNATURE_ENCODING");

	let signed_data = parts[0] + "." + parts[1];
	let valid = false;

	if (options.alg == "RS256") {
		valid = native.verify_rs256(signed_data, signature, pubkey);
	} else if (options.alg == "ES256") {
		valid = native.verify_es256(signed_data, signature, pubkey);
	} else {
		return Result.err("UNSUPPORTED_ALGORITHM", options.alg);
	}

	if (!valid) return Result.err("INVALID_SIGNATURE");

	// 5. Decode Payload JSON
	let res_p = safe_json(payload_json);
	if (!res_p.ok) return Result.err("INVALID_PAYLOAD_JSON");
	let payload = res_p.data;

	// 6. Claims Validation
	let clock_tolerance = options.clock_tolerance;
	let now = options.now;

	if (payload.exp != null) {
		if (type(payload.exp) != "int") return Result.err("INVALID_EXP_CLAIM");
		if (payload.exp < (now - clock_tolerance)) return Result.err("TOKEN_EXPIRED");
	}

	if (payload.nbf != null) {
		if (type(payload.nbf) != "int") return Result.err("INVALID_NBF_CLAIM");
		if (payload.nbf > (now + clock_tolerance)) return Result.err("TOKEN_NOT_YET_VALID");
	}

	if (payload.iat != null) {
		if (type(payload.iat) != "int") return Result.err("INVALID_IAT_CLAIM");
		if (payload.iat > (now + clock_tolerance)) return Result.err("TOKEN_ISSUED_IN_FUTURE");
	}

	if (options.iss && !constant_time_eq(encoding.normalize_url(payload.iss), encoding.normalize_url(options.iss))) {
		return Result.err("ISSUER_MISMATCH");
	}

	if (options.aud) {
		let aud = payload.aud;
		let found = false;
		if (type(aud) == "array") {
			if (length(aud) == 0) return Result.err("INVALID_AUDIENCE");
			for (let a in aud) {
				if (type(a) != "string") return Result.err("MALFORMED_AUDIENCE");
				if (constant_time_eq(a, options.aud)) {
					found = true;
					break;
				}
			}
		} else {
			found = constant_time_eq(aud, options.aud);
		}

		if (!found) {
			return Result.err("AUDIENCE_MISMATCH");
		}
	}

	return Result.ok(payload);
};

/**
 * Generates cryptographically secure random bytes.
 * 
 * @param {number} [len=32] - Number of bytes to generate
 * @returns {object} - Result Object {ok, data/error}
 */
export function random(len) {
	let byte_len = len || 32;
	if (type(byte_len) != "int") die("CONTRACT_VIOLATION: random expects integer length");

	// TESTING HOOK: Allow simulating CSPRNG failure
	let bytes = null;
	if (!global.TESTING_RANDOM_FAIL) {
		bytes = native.random(byte_len);
	}

	if (!bytes || type(bytes) != "string" || length(bytes) != byte_len) {
		return Result.err("CSPRNG_FAILURE");
	}

	return Result.ok(bytes);
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
 * Calculates SHA256 hash and returns it as a 64-character hex digest.
 * 
 * @param {string} str - Data to hash
 * @returns {object} - Result Object {ok, data/error}
 */
export function sha256_hex(str) {
	let hash_bin = sha256(str);
	if (!hash_bin) return Result.err("CRYPTO_ERROR");

	let hex = "";
	for (let i = 0; i < length(hash_bin); i++) {
		hex += sprintf("%02x", ord(hash_bin, i));
	}
	return Result.ok(hex);
};

/**
 * Generates a PKCE Code Verifier.
 * 
 * @param {number} [len=43] - Length of verifier
 * @returns {object} - Result Object {ok, data/error}
 */
export function pkce_generate_verifier(len) {
	let byte_len = len || 43;
	if (byte_len < 32 || byte_len > 96) die("CONTRACT_VIOLATION: PKCE verifier must be 32-96 bytes");

	let res = random(byte_len);
	if (!res.ok) return res;

	return Result.ok(b64url_encode(res.data));
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
 * @returns {object} - Result Object {ok, data/error}
 */
export function pkce_pair(len) {
	let res = pkce_generate_verifier(len);
	if (!res.ok) return res;

	let verifier = res.data;
	let challenge = pkce_calculate_challenge(verifier);
	return Result.ok({ verifier, challenge });
};

/**
 * Converts a JWK object to a PEM string.
 */
export const jwk_to_pem = jwk.jwk_to_pem;

/**
 * Converts a sensitive token or handle into a safe, redacted correlation ID.
 * Uses the first 16 hex characters (64 bits) of the SHA256 hash.
 * 
 * NOTE: This 64-bit truncation provides a birthday collision bound of ~2^32.
 * This is considered acceptable for correlation IDs in router logs, but MUST
 * NOT be used for cryptographic identity or primary key indexing where
 * collisions could lead to security vulnerabilities.
 * 
 * @param {string} token - The sensitive token or handle.
 * @returns {string} - The 16-character safe ID, or '[INVALID]'.
 */
export function safe_id(token) {
	if (!token || type(token) != "string" || length(token) < 8) {
		return "[INVALID]";
	}

	let hash_bin = native.sha256(token);
	if (!hash_bin) return "[ERROR]";

	let hex = "";
	for (let i = 0; i < 8; i++) {
		hex += sprintf("%02x", ord(hash_bin, i));
	}

	return hex;
};
