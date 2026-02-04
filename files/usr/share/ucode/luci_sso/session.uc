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
		// If read fails (e.g. permission denied), we shouldn't continue
		return null;
	}

	if (!key) {
		key = crypto.random(32);
		try {
			io.write_file(SECRET_KEY_PATH, key);
		} catch (e) {
			// If we can't save the key, we can't ensure persistence
			// but we return the key for the current process
		}
	}
	return key;
};

/**
 * Creates a signed state token for the OIDC redirect.
 */
export function create_state(io, state, code_verifier, nonce) {
	let secret = get_secret_key(io);
	if (!secret) return null;

	let now = io.time();
	
	let payload = {
		state: state,
		code_verifier: code_verifier,
		nonce: nonce,
		iat: now,
		exp: now + HANDSHAKE_DURATION
	};
	
	return crypto.sign_jws(payload, secret);
};

/**
 * Verifies a state token.
 */
export function verify_state(io, token) {
	let secret = get_secret_key(io);
	if (!secret) return { error: "INTERNAL_ERROR", details: "Could not retrieve secret key" };

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
		return null;
	}

	let secret = get_secret_key(io);
	if (!secret) return null;

	let now = io.time();
	
	let payload = {
		user: user_data.email || user_data.sub,
		name: user_data.name,
		iat: now,
		exp: now + SESSION_DURATION
	};
	
	return crypto.sign_jws(payload, secret);
};

/**
 * Verifies a session token and returns the session object.
 */
export function verify(io, token) {
	if (!token) return { error: "NO_SESSION" };
	
	let secret = get_secret_key(io);
	if (!secret) return { error: "INTERNAL_ERROR", details: "Could not retrieve secret key" };

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
