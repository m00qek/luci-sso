import * as Result from 'luci_sso.result';
import * as encoding from 'luci_sso.encoding';
import * as base from 'luci_sso.crypto.base';

const MAX_TOKEN_SIZE = 16384; // 16 KB

function decode_header(raw_header, alg) {
	let header_json = encoding.b64url_decode(raw_header);
	if (!header_json)
    return Result.err("INVALID_HEADER_ENCODING");

	let res_h = encoding.safe_json(header_json);
	if (!res_h.ok || !res_h.data.alg)
    return Result.err("INVALID_HEADER_JSON");

	if (res_h.data.alg != alg) {
		return Result.err("ALGORITHM_MISMATCH", `Expected ${alg}, got ${res_h.data.alg}`);
	}

	return res_h;
}

/**
 * Parses and validates an OIDC JWT (Public Key: RS256/ES256).
 * 
 * @param {string} token - JWT string
 * @param {string} pubkey - PEM public key
 * @param {object} options - Validation options {alg, iss, aud, skew}
 * @returns {object} - Result Object {ok, data/error}
 */
export function jwt_verify(native, token, pubkey, options) {
	if (type(token) != "string")
    die("CONTRACT_VIOLATION: jwt_verify expects string token");

	if (type(pubkey) != "string")
    die("CONTRACT_VIOLATION: jwt_verify expects string pubkey");

	if (type(options) != "object")
    die("CONTRACT_VIOLATION: jwt_verify expects object options");

	if (type(options.now) != "int")
    die("CONTRACT_VIOLATION: jwt_verify expects mandatory integer options.now");

	if (type(options.clock_tolerance) != "int")
    die("CONTRACT_VIOLATION: jwt_verify expects mandatory integer options.clock_tolerance");

	if (length(token) > MAX_TOKEN_SIZE)
    return Result.err("TOKEN_TOO_LARGE");

	if (!options.alg)
    return Result.err("MISSING_ALGORITHM_OPTION");

	let parts = split(token, ".", 4);
	if (length(parts) != 3)
    return Result.err("MALFORMED_JWT");

	let header = decode_header(parts[0], options.alg);
  if (!header.ok) 
    return header;

	// 2. Decode and Validate Payload Encoding (Fail Fast)
	let payload_json = encoding.b64url_decode(parts[1]);
	if (!payload_json)
    return Result.err("INVALID_PAYLOAD_ENCODING");


	// 4. Decode and Verify Signature
	let signature = encoding.b64url_decode(parts[2]);
	if (!signature)
    return Result.err("INVALID_SIGNATURE_ENCODING");

	let signed_data = parts[0] + "." + parts[1];
	let valid = false;

	if (options.alg == "RS256") {
		valid = native.verify_rs256(signed_data, signature, pubkey);
	} else if (options.alg == "ES256") {
		valid = native.verify_es256(signed_data, signature, pubkey);
	} else {
		return Result.err("UNSUPPORTED_ALGORITHM", options.alg);
	}

	if (!valid)
    return Result.err("INVALID_SIGNATURE");

	// 5. Decode Payload JSON
	let res_p = encoding.safe_json(payload_json);
	if (!res_p.ok) return Result.err("INVALID_PAYLOAD_JSON");
	let payload = res_p.data;

	// 6. Claims Validation
	let clock_tolerance = options.clock_tolerance;
	let now = options.now;

	// MANDATORY: exp (Expiry) and iat (Issued At) MUST be present (Audit B2)
	// Both exp and iat are required for strict OIDC compliance and age validation.
	if (payload.exp == null) return Result.err("MISSING_EXP_CLAIM");
	if (payload.iat == null) return Result.err("MISSING_IAT_CLAIM");

	if (type(payload.exp) != "int") return Result.err("INVALID_EXP_CLAIM");
	if (payload.exp < (now - clock_tolerance)) return Result.err("TOKEN_EXPIRED");

	if (payload.nbf != null) {
		if (type(payload.nbf) != "int") return Result.err("INVALID_NBF_CLAIM");
		if (payload.nbf > (now + clock_tolerance)) return Result.err("TOKEN_NOT_YET_VALID");
	}

	if (type(payload.iat) != "int") return Result.err("INVALID_IAT_CLAIM");
	if (payload.iat > (now + clock_tolerance)) return Result.err("TOKEN_ISSUED_IN_FUTURE");

	if (options.iss && !base.constant_time_eq(encoding.normalize_url(payload.iss), encoding.normalize_url(options.iss))) {
		return Result.err("ISSUER_MISMATCH");
	}

	if (options.aud) {
		let aud = payload.aud;
		let found = false;
		if (type(aud) == "array") {
			if (length(aud) == 0) return Result.err("INVALID_AUDIENCE");
			for (let a in aud) {
				if (type(a) != "string") return Result.err("MALFORMED_AUDIENCE");
				if (base.constant_time_eq(a, options.aud)) {
					found = true;
					break;
				}
			}
		} else {
			found = base.constant_time_eq(aud, options.aud);
		}

		if (!found) {
			return Result.err("AUDIENCE_MISMATCH");
		}
	}

	return Result.ok(payload);
};
