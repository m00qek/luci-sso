import * as Result from 'luci_sso.result';
import * as encoding from 'luci_sso.encoding';
import * as base from 'luci_sso.crypto.base';

const LIMIT_TOKEN_SIZE = 16384; // 16 KB

function decode_header(raw_header, alg) {
	let h_res = encoding.b64url_decode(raw_header);
	if (!h_res.ok)
		return Result.err("INVALID_HEADER_ENCODING");

	let res_h = encoding.safe_json(h_res.data);
	if (!res_h.ok || !res_h.data.alg)
		return Result.err("INVALID_HEADER_JSON");

	if (res_h.data.alg != alg) {
		return Result.err("ALGORITHM_MISMATCH", `Expected ${alg}, got ${res_h.data.alg}`);
	}

	return res_h;
};

/**
 * Parses and validates an OIDC JWT (Public Key: RS256/ES256).
 * 
 * @param {object} native - Native crypto provider
 * @param {string} token - JWT string
 * @param {string} pubkey - PEM public key
 * @param {object} options - Validation options {alg, iss, aud, skew}
 * @returns {object} - Result Object {ok, data/error}
 */
export function verify(native, token, pubkey, options) {
	if (type(token) != "string")
		die("CONTRACT_VIOLATION: jwt.verify expects string token");

	if (type(pubkey) != "string")
		die("CONTRACT_VIOLATION: jwt.verify expects string pubkey");

	if (type(options) != "object")
		die("CONTRACT_VIOLATION: jwt.verify expects object options");

	if (type(options.now) != "int")
		die("CONTRACT_VIOLATION: jwt.verify expects mandatory integer options.now");

	if (type(options.clock_tolerance) != "int")
		die("CONTRACT_VIOLATION: jwt.verify expects mandatory integer options.clock_tolerance");

	if (length(token) > LIMIT_TOKEN_SIZE)
		return Result.err("TOKEN_TOO_LARGE");

	if (type(options.iss) != "string")
		die("CONTRACT_VIOLATION: jwt.verify expects mandatory string options.iss");

	if (type(options.aud) != "string")
		die("CONTRACT_VIOLATION: jwt.verify expects mandatory string options.aud");

	if (!options.alg)
		return Result.err("MISSING_ALGORITHM_OPTION");

	let parts = split(token, ".", 4);
	if (length(parts) != 3)
		return Result.err("MALFORMED_JWT");

	if (options.pre_parsed_header && type(options.pre_parsed_header) == "object") {
		if (options.pre_parsed_header.alg != options.alg)
			return Result.err("ALGORITHM_MISMATCH", `Expected ${options.alg}, got ${options.pre_parsed_header.alg}`);
	} else {
		let header_res = decode_header(parts[0], options.alg);
		if (!header_res.ok)
			return header_res;
	}

	// 2. Decode Payload Encoding (Fail Fast)
	let p_res = encoding.b64url_decode(parts[1]);
	if (!p_res.ok)
		return Result.err("INVALID_PAYLOAD_ENCODING");

	// 4. Decode and Verify Signature
	let s_res = encoding.b64url_decode(parts[2]);
	if (!s_res.ok || length(s_res.data) == 0)
		return Result.err("INVALID_SIGNATURE_ENCODING");

	let signed_data = parts[0] + "." + parts[1];
	let valid = false;

	if (options.alg == "RS256") {
		valid = native.verify_rs256(signed_data, s_res.data, pubkey);
	} else if (options.alg == "ES256") {
		valid = native.verify_es256(signed_data, s_res.data, pubkey);
	} else {
		return Result.err("UNSUPPORTED_ALGORITHM", options.alg);
	}

	if (!valid)
		return Result.err("INVALID_SIGNATURE");

	// 5. Decode Payload JSON
	let res_p = encoding.safe_json(p_res.data);
	if (!res_p.ok) return Result.err("INVALID_PAYLOAD_JSON");
	let payload = res_p.data;

	// 6. Claims Validation
	let clock_tolerance = options.clock_tolerance;
	let now = options.now;

	// MANDATORY: exp (Expiry) and iat (Issued At) MUST be present
	// Both exp and iat are required for strict OIDC compliance and age validation.
	if (payload.exp == null) 
    return Result.err("MISSING_EXP_CLAIM");
	if (payload.iat == null)
    return Result.err("MISSING_IAT_CLAIM");

	if (type(payload.exp) != "int")
    return Result.err("INVALID_EXP_CLAIM");
	if (payload.exp < (now - clock_tolerance))
    return Result.err("TOKEN_EXPIRED");

	if (payload.nbf != null) {
		if (type(payload.nbf) != "int")
      return Result.err("INVALID_NBF_CLAIM");

		if (payload.nbf > (now + clock_tolerance))
      return Result.err("TOKEN_NOT_YET_VALID");
	}

	if (type(payload.iat) != "int")
    return Result.err("INVALID_IAT_CLAIM");
	if (payload.iat > (now + clock_tolerance))
    return Result.err("TOKEN_ISSUED_IN_FUTURE");

	let p_iss = encoding.normalize_url(payload.iss);
	let o_iss = encoding.normalize_url(options.iss);
	if (!p_iss.ok || !o_iss.ok || !base.constant_time_eq(p_iss.data, o_iss.data))
		return Result.err("ISSUER_MISMATCH");

	let aud = payload.aud;
	let found = false;
	if (type(aud) == "array") {
		if (length(aud) == 0)
			return Result.err("INVALID_AUDIENCE");

		for (let a in aud) {
			if (type(a) != "string")
				return Result.err("MALFORMED_AUDIENCE");

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

	return Result.ok(payload);
};
