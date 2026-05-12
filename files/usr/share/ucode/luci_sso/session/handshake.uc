import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import * as common from 'luci_sso.session.common';

/**
 * Handshake lifecycle management (OIDC transient state).
 */

/**
 * Performs an emergency reap of the oldest handshakes.
 * @private
 */
function _emergency_reap(io, files) {
	let candidates = [];
	for (let f in files) {
		if (match(f, /^handshake_.*\.json$/)) {
			let path = `${common.HANDSHAKE_DIR}/${f}`;
			let st = io.stat(path);
			push(candidates, { path: path, mtime: (st && st.mtime) || 0 });
		}
	}

	// Sort by oldest first
	sort(candidates, (a, b) => a.mtime - b.mtime);

	// Remove oldest 50%
	let to_remove = int(length(candidates) / 2);
	for (let i = 0; i < to_remove; i++) {
		try { io.remove(candidates[i].path); } catch (e) {}
	}
};

/**
 * Removes handshake files older than the duration.
 * @param {object} io - I/O provider
 * @param {number} clock_tolerance - Clock skew tolerance
 * @returns {object} - Result Object {ok, data: count/error}
 */
export function reap(io, clock_tolerance) {
	if (type(clock_tolerance) != "int") die("CONTRACT_VIOLATION: reap expects mandatory integer clock_tolerance");

	let files = io.lsdir(common.HANDSHAKE_DIR);
	if (!files) return Result.ok(0);

	let now = io.time();
	let reaped = 0;
	for (let f in files) {
		if (match(f, /^handshake_[A-Za-z0-9_-]+\.json$/)) {
			let path = `${common.HANDSHAKE_DIR}/${f}`;
			let st = io.stat(path);
			// Use a slightly larger grace period than duration + tolerance
			if (st && st.mtime && (now - st.mtime) > (common.HANDSHAKE_DURATION + clock_tolerance + common.REAP_GRACE_PERIOD)) {
				try { 
					io.remove(path);
					reaped++;
				} catch (e) {}
			}
		}
	}
	return Result.ok(reaped);
};

/**
 * Creates an opaque handshake state on the server.
 * 
 * @param {object} io - I/O provider
 * @returns {object} - Result Object {ok, data/error}
 */
export function create(io) {
	common.ensure_handshake_dir(io);

	// DOS PROTECTION: Check capacity before creating new state
	let files = io.lsdir(common.HANDSHAKE_DIR) || [];
	let count = 0;
	for (let f in files) {
		if (match(f, /^handshake_.*\.json$/)) count++;
	}

	if (count >= common.HANDSHAKE_MAX_COUNT) {
		io.log("warn", `Handshake capacity reached (${count}); triggering emergency reap`);
		_emergency_reap(io, files);
	}

	let res_p = crypto.pkce_pair();
	let res_s = crypto.random(16);
	let res_n = crypto.random(16);
	let res_h = crypto.random(32);

	if (!res_p.ok || !res_s.ok || !res_n.ok || !res_h.ok) {
		io.log("error", "CRITICAL: CSPRNG failure during handshake state generation");
		return Result.err("CRYPTO_SYSTEM_FAILURE");
	}

	let pkce = res_p.data;
	let res_b64_s = encoding.b64url_encode(res_s.data);
	let res_b64_n = encoding.b64url_encode(res_n.data);
	let res_b64_h = encoding.b64url_encode(res_h.data);

	if (!res_b64_s.ok || !res_b64_n.ok || !res_b64_h.ok) {
		io.log("error", "CRITICAL: b64url_encode failure during handshake state generation");
		return Result.err("CRYPTO_SYSTEM_FAILURE");
	}

	let state = res_b64_s.data;
	let nonce = res_b64_n.data;
	let handle = res_b64_h.data;
	let now = io.time();

	let data = {
		id: crypto.safe_id(handle), // Correlation ID for logs
		state: state,
		code_verifier: pkce.verifier,
		nonce: nonce,
		iat: now,
		exp: now + common.HANDSHAKE_DURATION
	};
	
	try {
		let path = `${common.HANDSHAKE_DIR}/handshake_${handle}.json`;
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
export function consume(io, handle) {
	if (!handle || type(handle) != "string") return;
	if (!match(handle, /^[A-Za-z0-9_-]+$/)) return;

	let path = `${common.HANDSHAKE_DIR}/handshake_${handle}.json`;
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
export function verify(io, handle, clock_tolerance) {
	if (type(handle) != "string") die("CONTRACT_VIOLATION: verify expects string handle");
	if (type(clock_tolerance) != "int") die("CONTRACT_VIOLATION: verify expects mandatory integer clock_tolerance");

	// Ensure the handle is a safe filename (Base64URL only)
	if (!match(handle, /^[A-Za-z0-9_-]+$/)) {
		return Result.err("INVALID_HANDLE_FORMAT");
	}

	let path = `${common.HANDSHAKE_DIR}/handshake_${handle}.json`;
	let consume_path = `${path}.consumed`;
	let content = null;
	let session_id = crypto.safe_id(handle);

	try {
		// MANDATORY: Atomic one-time use.
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

	// Validate mandatory handshake fields on load
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

	// Enforce mandatory exp and iat claims
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
