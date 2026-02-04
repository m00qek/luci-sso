import * as crypto from 'luci_sso.crypto';

const SECRET_KEY_PATH = "/etc/luci-sso/secret.key";
const SESSION_DURATION = 3600;
const SESSION_SKEW = 60;
const HANDSHAKE_DURATION = 300;
const HANDSHAKE_SKEW = 30;

/**
 * Internal helper to get/generate the router secret key.
 */
function get_secret_key(io) {
	let key = null;
	try {
		key = io.read_file(SECRET_KEY_PATH);
	} catch (e) {
		return { error: "KEY_READ_ERROR" };
	}

	if (!key) {
		key = crypto.random(32);
		try {
			io.write_file(SECRET_KEY_PATH, key);
		} catch (e) {
			// Non-fatal, but we'll lose persistence
		}
	}
	return { key: key };
};

/**
 * Creates a signed state token for the OIDC redirect.
 */
export function create_state(io, state, code_verifier, nonce) {
	let res = get_secret_key(io);
	if (res.error) return { error: "SECRET_KEY_ERROR", details: res.error };
	let secret = res.key;

	let now = io.time();
	let payload = {
		state: state,
		code_verifier: code_verifier,
		nonce: nonce,
		iat: now,
		exp: now + HANDSHAKE_DURATION
	};
	
	let token = crypto.sign_jws(payload, secret);
	return token ? { state: token } : { error: "SIGNING_FAILED" };
};

/**
 * Verifies a state token.
 */
export function verify_state(io, token) {
	let res = get_secret_key(io);
	if (res.error) return { error: "INTERNAL_ERROR", details: res.error };
	let secret = res.key;

	let result = crypto.verify_jws(token, secret);
	if (result.error) return result;
	
	let payload = result.payload;
	let now = io.time();

	if (payload.exp && payload.exp < (now - HANDSHAKE_SKEW)) {
		return { error: "HANDSHAKE_EXPIRED" };
	}

	if (payload.iat && payload.iat > (now + HANDSHAKE_SKEW)) {
		return { error: "HANDSHAKE_NOT_YET_VALID" };
	}
	
	return { payload: payload };
};

/**
 * Creates a signed session token.
 * @param {object} io - IO provider { read_file, write_file, time }
 * @param {object} user_data - User information from ID Token
 */
export function create(io, user_data) {
	if (!user_data || (type(user_data.sub) != "string" && type(user_data.email) != "string")) {
		return { error: "INVALID_USER_DATA" };
	}

	let res = get_secret_key(io);
	if (res.error) return { error: "SECRET_KEY_ERROR", details: res.error };
	let secret = res.key;

	let now = io.time();
	let payload = {
		user: user_data.email || user_data.sub,
		name: user_data.name,
		iat: now,
		exp: now + SESSION_DURATION
	};
	
	let token = crypto.sign_jws(payload, secret);
	return token ? { session: token } : { error: "SIGNING_FAILED" };
};

/**
 * Verifies a session token and returns the session object.
 */
export function verify(io, token) {
	if (!token) return { error: "NO_SESSION" };
	
	let res = get_secret_key(io);
	if (res.error) return { error: "INTERNAL_ERROR", details: res.error };
	let secret = res.key;

	let result = crypto.verify_jws(token, secret);
	if (result.error) return { error: "INVALID_SESSION", details: result.error };
	
	let session = result.payload;
	let now = io.time();
	
	if (session.exp && session.exp < (now - SESSION_SKEW)) {
		return { error: "SESSION_EXPIRED" };
	}

	if (session.iat && session.iat > (now + SESSION_SKEW)) {
		return { error: "SESSION_NOT_YET_VALID" };
	}
	
	return { session: session };
};
