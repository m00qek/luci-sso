import * as crypto from 'luci_sso.crypto';

const SECRET_KEY_PATH = "/etc/luci-sso/secret.key";
const SESSION_DURATION = 3600;

/**
 * Internal helper to get/generate the router secret key.
 */
function get_secret_key(io) {
	let key = io.read_file(SECRET_KEY_PATH);
	if (!key) {
		key = crypto.random(32);
		io.write_file(SECRET_KEY_PATH, key);
	}
	return key;
}

/**
 * Creates a signed session token.
 * @param {object} io - IO provider { read_file, write_file, time }
 * @param {object} user_data - User information from ID Token
 */
export function create_session(io, user_data) {
	let secret = get_secret_key(io);
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
export function verify_session(io, token) {
	if (!token) return { error: "NO_SESSION" };
	
	let secret = get_secret_key(io);
	let result = crypto.verify_jws(token, secret);
	
	if (result.error) return { error: "INVALID_SESSION", details: result.error };
	
	let session = result.payload;
	
	if (session.exp && session.exp < io.time()) {
		return { error: "SESSION_EXPIRED" };
	}
	
	return { session: session };
};
