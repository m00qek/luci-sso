import * as crypto from 'luci_sso.crypto';

const SECRET_KEY_PATH = "/etc/luci-sso/secret.key";
const SESSION_DURATION = 3600;
const SESSION_SKEW = 60;
const HANDSHAKE_DURATION = 300;
const HANDSHAKE_SKEW = 30;

/**
 * Validates the IO object.
 * @private
 */
function validate_io(io) {
	if (type(io) != "object" || 
		type(io.read_file) != "function" || 
		type(io.write_file) != "function" || 
		type(io.time) != "function" ||
		type(io.rename) != "function") {
		die("CONTRACT_VIOLATION: Invalid IO provider (missing rename support)");
	}
}

/**
 * Internal helper to get/generate the router secret key.
 * Uses atomic rename and re-read pattern to prevent race conditions.
 * @private
 */
function get_secret_key(io) {
	let key = null;
	try {
		key = io.read_file(SECRET_KEY_PATH);
	} catch (e) {
		// File missing or unreadable
	}

	if (!key || length(key) == 0) {
		// 1. Generate new key
		let new_key = crypto.random(32);
		let tmp_path = SECRET_KEY_PATH + ".tmp";
		
		try {
			// 2. Atomic Write Attempt: Write to .tmp, then Rename
			io.write_file(tmp_path, new_key);
			io.rename(tmp_path, SECRET_KEY_PATH);
		} catch (e) {
			// Failures here mean another process likely won or FS is read-only
		}

		// 3. CRITICAL: Re-read from disk to ensure all concurrent processes 
		// synchronize on the same "winner" key.
		try {
			key = io.read_file(SECRET_KEY_PATH);
		} catch (e) {
			// If re-read fails (e.g. read-only FS), use the local key as fallback
			key = new_key;
		}
	}
	return { ok: true, data: key };
}

/**
 * Creates a signed state token and all required OIDC params for redirect.
 * 
 * @param {object} io - I/O provider
 * @returns {object} - Result Object {ok, data/error}
 */
export function create_state(io) {
	validate_io(io);

	let res = get_secret_key(io);
	if (!res.ok) return res;
	let secret = res.data;

	let pkce = crypto.pkce_pair();
	let state = crypto.b64url_encode(crypto.random(16));
	let nonce = crypto.b64url_encode(crypto.random(16));
	let now = io.time();

	let payload = {
		state: state,
		code_verifier: pkce.verifier,
		nonce: nonce,
		iat: now,
		exp: now + HANDSHAKE_DURATION
	};
	
	let token = crypto.sign_jws(payload, secret);
	if (!token) return { ok: false, error: "SIGNING_FAILED" };

	return {
		ok: true,
		data: {
			token: token,
			state: state,
			nonce: nonce,
			code_challenge: pkce.challenge
		}
	};
};

/**
 * Verifies a state token.
 * 
 * @param {object} io - I/O provider
 * @param {string} token - Signed state token
 * @returns {object} - Result Object {ok, data/error}
 */
export function verify_state(io, token) {
	validate_io(io);
	if (type(token) != "string") die("CONTRACT_VIOLATION: verify_state expects string token");

	let res = get_secret_key(io);
	if (!res.ok) return res;
	let secret = res.data;

	let result = crypto.verify_jws(token, secret);
	if (!result.ok) return result;
	
	let payload = result.data;
	let now = io.time();

	if (payload.exp && payload.exp < (now - HANDSHAKE_SKEW)) {
		return { ok: false, error: "HANDSHAKE_EXPIRED" };
	}

	if (payload.iat && payload.iat > (now + HANDSHAKE_SKEW)) {
		return { ok: false, error: "HANDSHAKE_NOT_YET_VALID" };
	}
	
	return { ok: true, data: payload };
};

/**
 * Creates a signed session token.
 * 
 * @param {object} io - I/O provider
 * @param {object} user_data - User claims from ID token
 * @returns {object} - Result Object {ok, data/error}
 */
export function create(io, user_data) {
	validate_io(io);
	if (!user_data || (type(user_data.sub) != "string" && type(user_data.email) != "string")) {
		return { ok: false, error: "INVALID_USER_DATA" };
	}

	let res = get_secret_key(io);
	if (!res.ok) return res;
	let secret = res.data;

	let now = io.time();
	let payload = {
		user: user_data.email || user_data.sub,
		name: user_data.name,
		iat: now,
		exp: now + SESSION_DURATION
	};
	
	let token = crypto.sign_jws(payload, secret);
	return token ? { ok: true, data: token } : { ok: false, error: "SIGNING_FAILED" };
};

/**
 * Verifies a session token and returns the session object.
 * 
 * @param {object} io - I/O provider
 * @param {string} token - Signed session token
 * @returns {object} - Result Object {ok, data/error}
 */
export function verify(io, token) {
	validate_io(io);
	if (!token) return { ok: false, error: "NO_SESSION" };
	if (type(token) != "string") die("CONTRACT_VIOLATION: verify expects string token");
	
	let res = get_secret_key(io);
	if (!res.ok) return res;
	let secret = res.data;

	let result = crypto.verify_jws(token, secret);
	if (!result.ok) return { ok: false, error: "INVALID_SESSION", details: result.error };
	
	let session = result.data;
	let now = io.time();
	
	if (session.exp && session.exp < (now - SESSION_SKEW)) {
		return { ok: false, error: "SESSION_EXPIRED" };
	}

	if (session.iat && session.iat > (now + SESSION_SKEW)) {
		return { ok: false, error: "SESSION_NOT_YET_VALID" };
	}
	
	return { ok: true, data: session };
};
