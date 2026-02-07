import * as crypto from 'luci_sso.crypto';

const SECRET_KEY_PATH = "/etc/luci-sso/secret.key";
const SESSION_DURATION = 3600;
const HANDSHAKE_DURATION = 300;
const HANDSHAKE_DIR = "/var/run/luci-sso";

/**
 * Validates the IO object.
 * @private
 */
function validate_io(io) {
	if (type(io) != "object" || 
		type(io.read_file) != "function" || 
		type(io.write_file) != "function" || 
		type(io.time) != "function" ||
		type(io.rename) != "function" ||
		type(io.remove) != "function" ||
		type(io.mkdir) != "function" ||
		type(io.lsdir) != "function" ||
		type(io.stat) != "function") {
		die("CONTRACT_VIOLATION: Invalid IO provider");
	}
}

/**
 * Removes handshake files older than the duration.
 * @param {object} io - I/O provider
 * @param {number} clock_tolerance - Clock skew tolerance
 */
export function reap_stale_handshakes(io, clock_tolerance) {
	validate_io(io);
	if (type(clock_tolerance) != "int") die("CONTRACT_VIOLATION: reap_stale_handshakes expects mandatory integer clock_tolerance");

	let files = io.lsdir(HANDSHAKE_DIR);
	if (!files) return;

	let now = io.time();
	for (let f in files) {
		if (match(f, /^handshake_[A-Za-z0-9_-]+\.json$/)) {
			let path = `${HANDSHAKE_DIR}/${f}`;
			let st = io.stat(path);
			// Use a slightly larger grace period than duration + tolerance
			if (st && st.mtime && (now - st.mtime) > (HANDSHAKE_DURATION + clock_tolerance + 60)) {
				try { io.remove(path); } catch (e) {}
			}
		}
	}
};

/**
 * Internal helper to decode JSON safely.
 * @private
 */
function safe_json_parse(str) {
	try { return json(str); } catch (e) { return null; }
}

/**
 * Ensures the handshake directory exists.
 * @private
 */
function ensure_handshake_dir(io) {
	try {
		io.mkdir(HANDSHAKE_DIR, 0700);
	} catch (e) {
		// Might already exist or failed permissions, we'll find out on write
	}
}

/**
 * Internal helper to get/generate the router secret key.
 * Uses atomic rename and re-read pattern to prevent race conditions.
 * @private
 */
export function get_secret_key(io) {
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
		}

		if (!key) {
			key = new_key;
		}
	}
	return { ok: true, data: key };
};

/**
 * Creates an opaque handshake state on the server.
 * 
 * @param {object} io - I/O provider
 * @returns {object} - Result Object {ok, data/error}
 */
export function create_state(io) {
	validate_io(io);
	ensure_handshake_dir(io);

	let pkce = crypto.pkce_pair();
	let state = crypto.b64url_encode(crypto.random(16));
	let nonce = crypto.b64url_encode(crypto.random(16));
	let handle = crypto.b64url_encode(crypto.random(32));
	let now = io.time();

	let data = {
		state: state,
		code_verifier: pkce.verifier,
		nonce: nonce,
		iat: now,
		exp: now + HANDSHAKE_DURATION
	};
	
	try {
		let path = `${HANDSHAKE_DIR}/handshake_${handle}.json`;
		io.write_file(path, sprintf("%J", data));
	} catch (e) {
		if (io.log) io.log("error", `Failed to save handshake state: ${e}`);
		return { ok: false, error: "STATE_SAVE_FAILED" };
	}

	return {
		ok: true,
		data: {
			token: handle, // Opaque handle for the cookie
			state: state,
			nonce: nonce,
			code_challenge: pkce.challenge
		}
	};
};

/**
 * Verifies and consumes a handshake state handle.
 * 
 * @param {object} io - I/O provider
 * @param {string} handle - Opaque handshake handle
 * @param {number} clock_tolerance - Clock skew tolerance
 * @returns {object} - Result Object {ok, data/error}
 */
export function verify_state(io, handle, clock_tolerance) {
	validate_io(io);
	if (type(handle) != "string") die("CONTRACT_VIOLATION: verify_state expects string handle");
	if (type(clock_tolerance) != "int") die("CONTRACT_VIOLATION: verify_state expects mandatory integer clock_tolerance");

	// Ensure the handle is a safe filename (Base64URL only)
	if (!match(handle, /^[A-Za-z0-9_-]+$/)) {
		return { ok: false, error: "INVALID_HANDLE_FORMAT" };
	}

	let path = `${HANDSHAKE_DIR}/handshake_${handle}.json`;
	let content = null;

	try {
		content = io.read_file(path);
	} catch (e) {
		return { ok: false, error: "STATE_NOT_FOUND" };
	}

	if (!content) return { ok: false, error: "STATE_NOT_FOUND" };

	let data = safe_json_parse(content);
	if (!data) {
		try { io.remove(path); } catch (e) {}
		return { ok: false, error: "STATE_CORRUPTED" };
	}

	let now = io.time();

	if (data.exp && data.exp < (now - clock_tolerance)) {
		try { io.remove(path); } catch (e) {}
		return { ok: false, error: "HANDSHAKE_EXPIRED" };
	}

	if (data.iat && data.iat > (now + clock_tolerance)) {
		return { ok: false, error: "HANDSHAKE_NOT_YET_VALID" };
	}
	
	// MANDATORY: One-time use. Delete immediately after successful verification.
	try { io.remove(path); } catch (e) {}

	return { ok: true, data: data };
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
 * @param {number} clock_tolerance - Clock skew tolerance
 * @returns {object} - Result Object {ok, data/error}
 */
export function verify(io, token, clock_tolerance) {
	validate_io(io);
	if (!token) return { ok: false, error: "NO_SESSION" };
	if (type(token) != "string") die("CONTRACT_VIOLATION: verify expects string token");
	if (type(clock_tolerance) != "int") die("CONTRACT_VIOLATION: verify expects mandatory integer clock_tolerance");
	
	let res = get_secret_key(io);
	if (!res.ok) return res;
	let secret = res.data;

	let result = crypto.verify_jws(token, secret);
	if (!result.ok) return { ok: false, error: "INVALID_SESSION", details: result.error };
	
	let session = result.data;
	let now = io.time();
	
	if (session.exp && session.exp < (now - clock_tolerance)) {
		return { ok: false, error: "SESSION_EXPIRED" };
	}

	if (session.iat && session.iat > (now + clock_tolerance)) {
		return { ok: false, error: "SESSION_NOT_YET_VALID" };
	}
	
	return { ok: true, data: session };
};
