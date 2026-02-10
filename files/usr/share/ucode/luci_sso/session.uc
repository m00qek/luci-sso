import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';

const SECRET_KEY_PATH = "/etc/luci-sso/secret.key";
const SESSION_DURATION = 3600;
const HANDSHAKE_DURATION = 300;
const HANDSHAKE_DIR = "/var/run/luci-sso";

/**
 * Removes handshake files older than the duration.
 * @param {object} io - I/O provider
 * @param {number} clock_tolerance - Clock skew tolerance
 */
export function reap_stale_handshakes(io, clock_tolerance) {
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
		// 1. Atomic Lock Attempt: Try to create a lock directory
		const lock_path = SECRET_KEY_PATH + ".lock";
		let acquired = false;
		try {
			// Ensure parent directory exists (Avoid SYSTEM_INIT_FAILED on fresh boot)
			io.mkdir("/etc/luci-sso", 0700);
			acquired = io.mkdir(lock_path, 0700);
		} catch (e) {
			// Lock already held by another process
		}

		if (acquired) {
			try {
				// 2. We are the generator: Generate and Write
				let new_key = crypto.random(32);
				let tmp_path = SECRET_KEY_PATH + ".tmp";
				// MANDATORY: Restricted permissions for secrets
				io.write_file(tmp_path, new_key);
				io.chmod(tmp_path, 0600);
				io.rename(tmp_path, SECRET_KEY_PATH);
				key = new_key;
			} catch (e) {
				// Error during generation/write
			}
			// 3. ALWAYS release the lock
			try { io.remove(lock_path); } catch (e) {}
		} else {
			// 4. Lock held by another: Re-read to see if it's finished
			key = io.read_file(SECRET_KEY_PATH);
			if (!key || length(key) == 0) {
				// FAIL: Do not fallback to random key (avoids transient session invalidation)
				return { ok: false, error: "SYSTEM_KEY_UNAVAILABLE" };
			}
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
	ensure_handshake_dir(io);

	let pkce = crypto.pkce_pair();
	let state = crypto.b64url_encode(crypto.random(16));
	let nonce = crypto.b64url_encode(crypto.random(16));
	let handle = crypto.b64url_encode(crypto.random(32));
	let now = io.time();

	let data = {
		id: crypto.safe_id(handle), // Correlation ID for logs
		state: state,
		code_verifier: pkce.verifier,
		nonce: nonce,
		iat: now,
		exp: now + HANDSHAKE_DURATION
	};
	
	try {
		let path = `${HANDSHAKE_DIR}/handshake_${handle}.json`;
		if (!io.write_file(path, sprintf("%J", data))) {
			let err = io.fserror();
			io.log("error", `Failed to save handshake state: ${err}`);
			return { ok: false, error: "STATE_SAVE_FAILED", details: err };
		}
		io.chmod(path, 0600);
	} catch (e) {
		io.log("error", `Failed to save handshake state: ${e}`);
		return { ok: false, error: "STATE_SAVE_FAILED" };
	}

	io.log("info", `Handshake state created [session_id: ${data.id}]`);

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
 * Explicitly consumes (deletes) a handshake state.
 * Used for cleanup on terminal auth failures.
 * 
 * @param {object} io - I/O provider
 * @param {string} handle - Opaque handshake handle
 */
export function consume_state(io, handle) {
	if (!handle || type(handle) != "string") return;
	if (!match(handle, /^[A-Za-z0-9_-]+$/)) return;

	let path = `${HANDSHAKE_DIR}/handshake_${handle}.json`;
	try {
		io.remove(path);
	} catch (e) {}
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
	if (type(handle) != "string") die("CONTRACT_VIOLATION: verify_state expects string handle");
	if (type(clock_tolerance) != "int") die("CONTRACT_VIOLATION: verify_state expects mandatory integer clock_tolerance");

	// Ensure the handle is a safe filename (Base64URL only)
	if (!match(handle, /^[A-Za-z0-9_-]+$/)) {
		return { ok: false, error: "INVALID_HANDLE_FORMAT" };
	}

	let path = `${HANDSHAKE_DIR}/handshake_${handle}.json`;
	let consume_path = `${path}.consumed`;
	let content = null;
	let session_id = crypto.safe_id(handle);

	try {
		// MANDATORY: Atomic one-time use. (Blocker #2 in 1770660561)
		// We RENAME the file to .consumed. Only one process can succeed in the rename.
		if (!io.rename(path, consume_path)) {
			io.log("error", `Handshake state not found or already consumed [session_id: ${session_id}]`);
			return { ok: false, error: "STATE_NOT_FOUND" };
		}
		
		content = io.read_file(consume_path);
		if (content) io.remove(consume_path);
	} catch (e) {
		io.log("error", `Handshake state consumption failed [session_id: ${session_id}]: ${e}`);
		return { ok: false, error: "STATE_NOT_FOUND" };
	}

	if (!content) {
		io.log("error", `Handshake state content missing [session_id: ${session_id}]`);
		return { ok: false, error: "STATE_NOT_FOUND" };
	}

	let res = encoding.safe_json(content);
	if (!res.ok) {
		io.log("error", `Handshake state corrupted [session_id: ${session_id}]: ${res.details}`);
		return { ok: false, error: "STATE_CORRUPTED" };
	}
	let data = res.data;

	// B2: Validate mandatory handshake fields on load
	if (!data.code_verifier || type(data.code_verifier) != "string" || length(data.code_verifier) < 43) {
		io.log("error", `Handshake state missing or invalid PKCE verifier [session_id: ${session_id}]`);
		return { ok: false, error: "STATE_CORRUPTED" };
	}
	if (!data.state || type(data.state) != "string") {
		io.log("error", `Handshake state missing state parameter [session_id: ${session_id}]`);
		return { ok: false, error: "STATE_CORRUPTED" };
	}
	if (!data.nonce || type(data.nonce) != "string") {
		io.log("error", `Handshake state missing nonce [session_id: ${session_id}]`);
		return { ok: false, error: "STATE_CORRUPTED" };
	}

	let now = io.time();

	if (data.exp && data.exp < (now - clock_tolerance)) {
		io.log("warn", `Handshake state expired [session_id: ${session_id}]`);
		return { ok: false, error: "HANDSHAKE_EXPIRED" };
	}

	if (data.iat && data.iat > (now + clock_tolerance)) {
		io.log("warn", `Handshake state not yet valid [session_id: ${session_id}]`);
		return { ok: false, error: "HANDSHAKE_NOT_YET_VALID" };
	}
	
	io.log("info", `Handshake state successfully validated [session_id: ${session_id}]`);
	
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