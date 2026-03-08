import * as Result from 'luci_sso.result';
import * as encoding from 'luci_sso.encoding';
import * as base from 'luci_sso.crypto.base';

const MAX_TOKEN_SIZE = 16384; // 16 KB

/**
 * Signs a payload using HMAC-SHA256 and returns a JWS (Compact Serialization).
 * 
 * @param {object} payload - Data to sign
 * @param {string} secret - Binary secret key
 * @returns {object} - Result Object {ok, data/error}
 */
export function jws_sign(native, payload, secret) {
	if (type(payload) != "object")
    die("CONTRACT_VIOLATION: jws_sign expects object payload");

	if (type(secret) != "string")
    die("CONTRACT_VIOLATION: jws_sign expects string secret");

	let header = { alg: "HS256", typ: "JWT" };
	let b64_header = encoding.b64url_encode(sprintf("%J", header));
	let b64_payload = encoding.b64url_encode(sprintf("%J", payload));
	let signed_data = b64_header + "." + b64_payload;

	let signature = native.hmac_sha256(secret, signed_data);
	if (!signature)
    return Result.err("CRYPTO_ERROR", "hmac_sha256 failed");

	return Result.ok(signed_data + "." + encoding.b64url_encode(signature));
};

/**
 * Verifies a JWS (HMAC-SHA256) and returns the parsed payload if valid.
 * 
 * @param {string} token - Compact JWS string
 * @param {string} secret - Binary secret key
 * @returns {object} - Result Object {ok, data/error}
 */
export function jws_verify(native, token, secret) {
	if (type(token) != "string")
    die("CONTRACT_VIOLATION: jws_verify expects string token");

	if (type(secret) != "string")
    die("CONTRACT_VIOLATION: jws_verify expects string secret");

	if (length(token) > MAX_TOKEN_SIZE)
    return Result.err("TOKEN_TOO_LARGE");

	let parts = split(token, ".", 4);
	if (length(parts) != 3)
    return Result.err("MALFORMED_JWS");

	// 1. Decode and Validate Header
	let header_json = encoding.b64url_decode(parts[0]);
	if (!header_json)
    return Result.err("INVALID_HEADER_ENCODING");
	let res_h = encoding.safe_json(header_json);
	if (!res_h.ok)
    return Result.err("INVALID_HEADER_JSON");
	let header = res_h.data;
	if (header.alg != "HS256")
		return Result.err("UNSUPPORTED_ALGORITHM", header.alg);

	// 2. Verify Signature
	let signed_data = parts[0] + "." + parts[1];
	let provided_sig = encoding.b64url_decode(parts[2]);
	if (!provided_sig)
    return Result.err("INVALID_SIGNATURE_ENCODING");

	let calculated_sig = native.hmac_sha256(secret, signed_data);
	if (!calculated_sig || !base.constant_time_eq(calculated_sig, provided_sig))
		return Result.err("INVALID_SIGNATURE");

	// 3. Decode Payload
	let payload_json = encoding.b64url_decode(parts[1]);
	if (!payload_json)
    return Result.err("INVALID_PAYLOAD_ENCODING");
	let res_p = encoding.safe_json(payload_json);
	if (!res_p.ok)
    return Result.err("INVALID_PAYLOAD_JSON");
	let payload = res_p.data;

	return Result.ok(payload);
};
