import * as Result from 'luci_sso.result';
import * as encoding from 'luci_sso.encoding';
import * as base from 'luci_sso.crypto.base';

const MAX_TOKEN_SIZE = 16384; // 16 KB

/**
 * Signs a payload using HMAC-SHA256 and returns a JWS (Compact Serialization).
 * 
 * @param {object} native - Native crypto provider
 * @param {object} payload - Data to sign
 * @param {string} secret - Binary secret key
 * @returns {object} - Result Object {ok, data/error}
 */
export function sign(native, payload, secret) {
	if (type(payload) != "object")
		die("CONTRACT_VIOLATION: jws.sign expects object payload");

	if (type(secret) != "string")
		die("CONTRACT_VIOLATION: jws.sign expects string secret");

	let header = { alg: "HS256", typ: "JWT" };
	let h_res = encoding.b64url_encode(sprintf("%J", header));
	let p_res = encoding.b64url_encode(sprintf("%J", payload));

	if (!h_res.ok || !p_res.ok)
		return Result.err("ENCODE_ERROR");

	let signed_data = h_res.data + "." + p_res.data;

	let signature = native.hmac_sha256(secret, signed_data);
	if (!signature)
		return Result.err("CRYPTO_ERROR", "hmac_sha256 failed");

	let s_res = encoding.b64url_encode(signature);
	if (!s_res.ok)
		return Result.err("ENCODE_ERROR");

	return Result.ok(signed_data + "." + s_res.data);
};

/**
 * Verifies a JWS (HMAC-SHA256) and returns the parsed payload if valid.
 * 
 * @param {object} native - Native crypto provider
 * @param {string} token - Compact JWS string
 * @param {string} secret - Binary secret key
 * @returns {object} - Result Object {ok, data/error}
 */
export function verify(native, token, secret) {
	if (type(token) != "string")
		die("CONTRACT_VIOLATION: jws.verify expects string token");

	if (type(secret) != "string")
		die("CONTRACT_VIOLATION: jws.verify expects string secret");

	if (length(token) > MAX_TOKEN_SIZE)
		return Result.err("TOKEN_TOO_LARGE");

	let parts = split(token, ".", 4);
	if (length(parts) != 3)
		return Result.err("MALFORMED_JWS");

	// 1. Decode and Validate Header
	let h_res = encoding.b64url_decode(parts[0]);
	if (!h_res.ok)
		return Result.err("INVALID_HEADER_ENCODING");
	
	let res_h = encoding.safe_json(h_res.data);
	if (!res_h.ok)
		return Result.err("INVALID_HEADER_JSON");
	
	let header = res_h.data;
	if (header.alg != "HS256")
		return Result.err("UNSUPPORTED_ALGORITHM", header.alg);

	// 2. Verify Signature
	let signed_data = parts[0] + "." + parts[1];
	let s_res = encoding.b64url_decode(parts[2]);
	if (!s_res.ok)
		return Result.err("INVALID_SIGNATURE_ENCODING");

	let calculated_sig = native.hmac_sha256(secret, signed_data);
	if (!calculated_sig || !base.constant_time_eq(calculated_sig, s_res.data))
		return Result.err("INVALID_SIGNATURE");

	// 3. Decode Payload
	let p_res = encoding.b64url_decode(parts[1]);
	if (!p_res.ok)
		return Result.err("INVALID_PAYLOAD_ENCODING");
	
	let res_p = encoding.safe_json(p_res.data);
	if (!res_p.ok)
		return Result.err("INVALID_PAYLOAD_JSON");

	return Result.ok(res_p.data);
};
