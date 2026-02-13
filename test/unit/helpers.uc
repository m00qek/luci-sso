import * as crypto from 'luci_sso.crypto';
import * as fs from 'fs';

/**
 * Generates a signed HS256 JWT for internal session testing.
 */
export function generate_internal_token(payload, secret) {
	return crypto.sign_jws(payload, secret);
};

/**
 * Generates a high-fidelity signed JWT (RS256 or ES256) for OIDC logic testing.
 * Shells out to openssl for signing since native bindings only support verification.
 */
export function generate_id_token(payload, privkey_pem, alg) {
	let header = { alg: alg || "RS256", typ: "JWT" };
	let b64_header = crypto.b64url_encode(sprintf("%J", header));
	let b64_payload = crypto.b64url_encode(sprintf("%J", payload));
	let signed_data = b64_header + "." + b64_payload;

	// Use temporary files for signing data and key
	let data_tmp = "/tmp/jwt_data.tmp";
	let key_tmp = "/tmp/jwt_key.tmp";
	fs.writefile(data_tmp, signed_data);
	fs.writefile(key_tmp, privkey_pem);

	let cmd = "";
	if (header.alg == "RS256") {
		cmd = sprintf("openssl dgst -sha256 -sign %s %s", key_tmp, data_tmp);
	} else if (header.alg == "ES256") {
		// OpenSSL outputs DER for ECDSA, but JWS expects RAW (64 bytes)
		// We'll use a simple shell pipe to convert DER to RAW if possible,
		// but for simplicity in unit tests, we'll implement a basic DER-to-RAW in ucode
		cmd = sprintf("openssl dgst -sha256 -sign %s %s", key_tmp, data_tmp);
	}

	let p = fs.popen(cmd);
	let sig_bin = p.read("all");
	p.close();

	fs.unlink(data_tmp);
	fs.unlink(key_tmp);

	if (header.alg == "ES256") {
		// Convert DER (OpenSSL) to RAW (JWS)
		// This is a minimal implementation for P-256 (32-byte R, 32-byte S)
		// DER: 0x30 | len | 0x02 | lenR | R | 0x02 | lenS | S
		let r_len = ord(sig_bin, 3);
		let r_start = 4;
		if (r_len > 32) { r_start += (r_len - 32); r_len = 32; }
		let r = substr(sig_bin, r_start, r_len);
		while (length(r) < 32) r = "\0" + r;

		let s_idx = 4 + ord(sig_bin, 3);
		let s_len = ord(sig_bin, s_idx + 1);
		let s_start = s_idx + 2;
		if (s_len > 32) { s_start += (s_len - 32); s_len = 32; }
		let s = substr(sig_bin, s_start, s_len);
		while (length(s) < 32) s = "\0" + s;

		sig_bin = r + s;
	}

	return signed_data + "." + crypto.b64url_encode(sig_bin);
};