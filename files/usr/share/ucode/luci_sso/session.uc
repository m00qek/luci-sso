import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';

const SECRET_KEY_PATH = "/etc/luci-sso/secret.key";
const SESSION_DURATION = 3600;
const HANDSHAKE_DURATION = 300;
const HANDSHAKE_DIR = "/var/run/luci-sso";
const REAP_GRACE_PERIOD = 60;

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
			if (st && st.mtime && (now - st.mtime) > (HANDSHAKE_DURATION + clock_tolerance + REAP_GRACE_PERIOD)) {
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
				let res = crypto.random(32);
				if (!res.ok) {
					io.log("error", "CRITICAL: CSPRNG failure during secret key generation");
					try { io.remove(lock_path); } catch (e) {}
					return Result.err("CRYPTO_SYSTEM_FAILURE");
				}

				let new_key = res.data;
				let tmp_path = SECRET_KEY_PATH + ".tmp";
				// MANDATORY: Restricted permissions for secrets
				if (!io.write_file(tmp_path, new_key)) {
					io.log("error", "CRITICAL: Failed to write secret key");
					try { io.remove(lock_path); } catch (e) {}
					return Result.err("SYSTEM_KEY_WRITE_FAILED");
				}
				io.chmod(tmp_path, 0600);
				io.rename(tmp_path, SECRET_KEY_PATH);
				key = new_key;
			} catch (e) {
				// Error during generation/write
			}
			// 3. ALWAYS release the lock
			try { io.remove(lock_path); } catch (e) {}
		} else {
			// 4. BLOCKER FIX: Retry with backoff if lock is held (B2)
			let retries = 0;
			const max_retries = 5;

			while (retries < max_retries) {
				// Wait for a clock tick (at least 1 second in production)
				io.sleep(1);

				try {
					key = io.read_file(SECRET_KEY_PATH);
				} catch (e) {
					// File still missing or unreadable
				}

				if (key && length(key) > 0) break;
				retries++;
			}

			if (!key || length(key) == 0) {
				// FAIL: Do not fallback to random key (avoids transient session invalidation)
				return Result.err("SYSTEM_KEY_UNAVAILABLE");
			}
		}
	}
	return Result.ok(key);
};

/**
 * Creates an opaque handshake state on the server.
 * 
 * @param {object} io - I/O provider
 * @returns {object} - Result Object {ok, data/error}
 */
export function create_state(io) {
	ensure_handshake_dir(io);

	let res_p = crypto.pkce_pair();
	let res_s = crypto.random(16);
	let res_n = crypto.random(16);
	let res_h = crypto.random(32);

	if (!res_p.ok || !res_s.ok || !res_n.ok || !res_h.ok) {
		io.log("error", "CRITICAL: CSPRNG failure during handshake state generation");
		return Result.err("CRYPTO_SYSTEM_FAILURE");
	}

	let pkce = res_p.data;
	let state = crypto.b64url_encode(res_s.data);
	let nonce = crypto.b64url_encode(res_n.data);
	let handle = crypto.b64url_encode(res_h.data);
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
		let tmp_path = `${path}.tmp`;

		if (!io.write_file(tmp_path, sprintf("%J", data))) {
			let err = io.fserror();
			io.log("error", `Failed to save handshake state (write): ${err}`);
			return Result.err("STATE_SAVE_FAILED", err);
		}

		io.chmod(tmp_path, 0600);

		if (!io.rename(tmp_path, path)) {
			let err = io.fserror();
			io.log("error", `Failed to save handshake state (rename): ${err}`);
			try { io.remove(tmp_path); } catch (e) {}
			return Result.err("STATE_SAVE_FAILED", err);
		}
	} catch (e) {
		io.log("error", `Failed to save handshake state: ${e}`);
		return Result.err("STATE_SAVE_FAILED");
	}

	io.log("info", `Handshake state created [session_id: ${data.id}]`);

	return Result.ok({
		token: handle, // Opaque handle for the cookie
		state: state,
		nonce: nonce,
		code_challenge: pkce.challenge
	});
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
		return Result.err("INVALID_HANDLE_FORMAT");
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
			return Result.err("STATE_NOT_FOUND");
		}
		
		content = io.read_file(consume_path);
	} catch (e) {
		io.log("error", `Handshake state consumption failed [session_id: ${session_id}]: ${e}`);
		// Attempt to cleanup the consumed file if it exists but failed to read/process
		try { io.remove(consume_path); } catch (e) {}
		return Result.err("STATE_NOT_FOUND");
	}

	// Always remove the consumed file immediately
	try { io.remove(consume_path); } catch (e) {}

	if (!content) {
		io.log("error", `Handshake state content missing [session_id: ${session_id}]`);
		return Result.err("STATE_NOT_FOUND");
	}

	let res = encoding.safe_json(content);
	if (!res.ok) {
		io.log("error", `Handshake state corrupted [session_id: ${session_id}]: ${res.details}`);
		return Result.err("STATE_CORRUPTED");
	}
	let data = res.data;

	// B2: Validate mandatory handshake fields on load
	if (!data.code_verifier || type(data.code_verifier) != "string" || length(data.code_verifier) < 43 || length(data.code_verifier) > 128) {
		io.log("error", `Handshake state missing or invalid PKCE verifier [session_id: ${session_id}]`);
		return Result.err("STATE_CORRUPTED");
	}
	if (!data.state || type(data.state) != "string") {
		io.log("error", `Handshake state missing state parameter [session_id: ${session_id}]`);
		return Result.err("STATE_CORRUPTED");
	}
	if (!data.nonce || type(data.nonce) != "string") {
		io.log("error", `Handshake state missing nonce [session_id: ${session_id}]`);
		return Result.err("STATE_CORRUPTED");
	}

	// W5: Enforce mandatory exp and iat claims
	if (data.exp == null || type(data.exp) != "int") {
		io.log("error", `Handshake state missing or invalid 'exp' [session_id: ${session_id}]`);
		return Result.err("STATE_CORRUPTED");
	}
	if (data.iat == null || type(data.iat) != "int") {
		io.log("error", `Handshake state missing or invalid 'iat' [session_id: ${session_id}]`);
		return Result.err("STATE_CORRUPTED");
	}

	let now = io.time();

	if (data.exp < (now - clock_tolerance)) {
		io.log("warn", `Handshake state expired [session_id: ${session_id}]`);
		return Result.err("HANDSHAKE_EXPIRED");
	}

	if (data.iat > (now + clock_tolerance)) {
		io.log("warn", `Handshake state not yet valid [session_id: ${session_id}]`);
		return Result.err("HANDSHAKE_NOT_YET_VALID");
	}
	
	io.log("info", `Handshake state successfully validated [session_id: ${session_id}]`);
	
	return Result.ok(data);
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
		return Result.err("INVALID_USER_DATA");
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
	
	return crypto.sign_jws(payload, secret);
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
	if (!token) return Result.err("NO_SESSION");
	if (type(token) != "string") die("CONTRACT_VIOLATION: verify expects string token");
	if (type(clock_tolerance) != "int") die("CONTRACT_VIOLATION: verify expects mandatory integer clock_tolerance");
	
	let res = get_secret_key(io);
	if (!res.ok) return res;
	let secret = res.data;

	let result = crypto.verify_jws(token, secret);
	if (!result.ok) return Result.err("INVALID_SESSION", result.error);
	
	let session = result.data;
	let now = io.time();
	
	if (session.exp == null || type(session.exp) != "int") {
		return Result.err("INVALID_SESSION");
	}
	if (session.exp < (now - clock_tolerance)) {
		return Result.err("SESSION_EXPIRED");
	}

	if (session.iat == null || type(session.iat) != "int") {
		return Result.err("INVALID_SESSION");
	}
	if (session.iat > (now + clock_tolerance)) {
		return Result.err("SESSION_NOT_YET_VALID");
	}
	
	return Result.ok(session);
};