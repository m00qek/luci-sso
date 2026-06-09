import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import * as common from 'luci_sso.session.common';
import { CRYPTO_INIT_FAILED, STATE_SAVE_FAILED, MALFORMED_STATE_COOKIE, STATE_NOT_FOUND, STATE_CORRUPTED, HANDSHAKE_EXPIRED, HANDSHAKE_NOT_YET_VALID, HANDSHAKE_CAPACITY_EXCEEDED } from 'luci_sso.errors';

/**
 * Handshake lifecycle management (OIDC transient state).
 */

/**
 * Performs an emergency reap of the oldest handshakes.
 * @private
 */
function _emergency_reap(deps, files) {
	let candidates = [];
	for (let f in files) {
		if (match(f, /^handshake_.*\.json$/)) {
			let path = `${common.HANDSHAKE_DIR}/${f}`;
			let st = deps.fs.stat(path);
			push(candidates, { path: path, mtime: (st && st.mtime) || 0 });
		}
	}

	// Sort by oldest first
	sort(candidates, (a, b) => a.mtime - b.mtime);

	// Remove oldest 50%
	let to_remove = int(length(candidates) / 2);
	for (let i = 0; i < to_remove; i++) {
		try { deps.fs.unlink(candidates[i].path); } catch (e) {}
	}
};

/**
 * Removes handshake files older than the duration.
 * @param {object} deps - { fs, clock, log }
 * @param {number} clock_tolerance - Clock skew tolerance
 * @returns {object} - Result Object {ok, data: count/error}
 */
export function reap(deps, clock_tolerance) {
	if (type(clock_tolerance) !== "int") die("CONTRACT_VIOLATION: reap expects mandatory integer clock_tolerance");

	let files = deps.fs.lsdir(common.HANDSHAKE_DIR);
	if (!files) return Result.ok(0);

	let now = deps.clock.time();
	let reaped = 0;
	for (let f in files) {
		if (match(f, /^handshake_[A-Za-z0-9_-]+\.json$/)) {
			let path = `${common.HANDSHAKE_DIR}/${f}`;
			let st = deps.fs.stat(path);
			// Use a slightly larger grace period than duration + tolerance
			if (st && st.mtime && (now - st.mtime) > (common.HANDSHAKE_DURATION + clock_tolerance + common.REAP_GRACE_PERIOD)) {
				try {
					deps.fs.unlink(path);
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
 * @param {object} deps - { fs, clock, log }
 * @returns {object} - Result Object {ok, data/error}
 */
export function create(deps) {
	common.ensure_handshake_dir(deps);

	// DOS PROTECTION: Check capacity before creating new state
	let files = deps.fs.lsdir(common.HANDSHAKE_DIR) || [];
	let count = 0;
	for (let f in files) {
		if (match(f, /^handshake_.*\.json$/)) count++;
	}

	if (count >= common.HANDSHAKE_MAX_COUNT) {
		deps.log("warn", `Handshake capacity reached (${count}); triggering emergency reap`);
		_emergency_reap(deps, files);
		let new_count = 0;
		let refreshed = deps.fs.lsdir(common.HANDSHAKE_DIR) || [];
		for (let f in refreshed) {
			if (match(f, /^handshake_.*\.json$/)) new_count++;
		}
		if (new_count >= common.HANDSHAKE_MAX_COUNT) {
			deps.log("error", `Handshake capacity still exceeded after emergency reap (${new_count}); rejecting`);
			return Result.err(HANDSHAKE_CAPACITY_EXCEEDED);
		}
	}

	let res_p = crypto.pkce_pair();
	let res_s = crypto.random(16);
	let res_n = crypto.random(16);
	let res_h = crypto.random(32);

	if (!res_p.ok || !res_s.ok || !res_n.ok || !res_h.ok) {
		deps.log("error", "CRITICAL: CSPRNG failure during handshake state generation");
		return Result.err(CRYPTO_INIT_FAILED);
	}

	let pkce = res_p.data;
	let res_b64_s = encoding.b64url_encode(res_s.data);
	let res_b64_n = encoding.b64url_encode(res_n.data);
	let res_b64_h = encoding.b64url_encode(res_h.data);

	if (!res_b64_s.ok || !res_b64_n.ok || !res_b64_h.ok) {
		deps.log("error", "CRITICAL: b64url_encode failure during handshake state generation");
		return Result.err(CRYPTO_INIT_FAILED);
	}

	let state = res_b64_s.data;
	let nonce = res_b64_n.data;
	let handle = res_b64_h.data;
	let now = deps.clock.time();

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

		if (!deps.fs.writefile(tmp_path, sprintf("%J", data))) {
			let err = deps.fs.error();
			deps.log("error", `Failed to save handshake state (write): ${err}`);
			return Result.err(STATE_SAVE_FAILED, err);
		}

		deps.fs.chmod(tmp_path, 0600);

		if (!deps.fs.rename(tmp_path, path)) {
			let err = deps.fs.error();
			deps.log("error", `Failed to save handshake state (rename): ${err}`);
			try { deps.fs.unlink(tmp_path); } catch (e) {}
			return Result.err(STATE_SAVE_FAILED, err);
		}
	} catch (e) {
		deps.log("error", `Failed to save handshake state: ${e}`);
		return Result.err(STATE_SAVE_FAILED);
	}

	deps.log("info", `Handshake state created [session_id: ${data.id}]`);

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
 * @param {object} deps - { fs }
 * @param {string} handle - Opaque handshake handle
 */
export function consume(deps, handle) {
	if (!handle || type(handle) !== "string") return;
	if (!match(handle, /^[A-Za-z0-9_-]+$/)) return;

	let path = `${common.HANDSHAKE_DIR}/handshake_${handle}.json`;
	try {
		deps.fs.unlink(path);
	} catch (e) {}
};

/**
 * Verifies and consumes a handshake state handle.
 *
 * @param {object} deps - { fs, clock, log }
 * @param {string} handle - Opaque handshake handle
 * @param {number} clock_tolerance - Clock skew tolerance
 * @returns {object} - Result Object {ok, data/error}
 */
export function verify(deps, handle, clock_tolerance) {
	if (type(handle) !== "string") die("CONTRACT_VIOLATION: verify expects string handle");
	if (type(clock_tolerance) !== "int") die("CONTRACT_VIOLATION: verify expects mandatory integer clock_tolerance");

	// Ensure the handle is a safe filename (Base64URL only)
	if (!match(handle, /^[A-Za-z0-9_-]+$/)) {
		return Result.err(MALFORMED_STATE_COOKIE);
	}

	let path = `${common.HANDSHAKE_DIR}/handshake_${handle}.json`;
	let consume_path = `${path}.consumed`;
	let content = null;
	let session_id = crypto.safe_id(handle);

	try {
		// MANDATORY: Atomic one-time use.
		// We RENAME the file to .consumed. Only one process can succeed in the rename.
		if (!deps.fs.rename(path, consume_path)) {
			deps.log("error", `Handshake state not found or already consumed [session_id: ${session_id}]`);
			return Result.err(STATE_NOT_FOUND);
		}

		content = deps.fs.readfile(consume_path);
	} catch (e) {
		deps.log("error", `Handshake state consumption failed [session_id: ${session_id}]: ${e}`);
		// Attempt to cleanup the consumed file if it exists but failed to read/process
		try { deps.fs.unlink(consume_path); } catch (e) {}
		return Result.err(STATE_NOT_FOUND);
	}

	// Always remove the consumed file immediately
	try { deps.fs.unlink(consume_path); } catch (e) {}

	if (!content) {
		deps.log("error", `Handshake state content missing [session_id: ${session_id}]`);
		return Result.err(STATE_NOT_FOUND);
	}

	let res = encoding.safe_json(content);
	if (!res.ok) {
		deps.log("error", `Handshake state corrupted [session_id: ${session_id}]: ${res.details}`);
		return Result.err(STATE_CORRUPTED);
	}
	let data = res.data;

	// Validate mandatory handshake fields on load
	if (!data.code_verifier || type(data.code_verifier) !== "string" || length(data.code_verifier) < 43 || length(data.code_verifier) > 128) {
		deps.log("error", `Handshake state missing or invalid PKCE verifier [session_id: ${session_id}]`);
		return Result.err(STATE_CORRUPTED);
	}
	if (!data.state || type(data.state) !== "string") {
		deps.log("error", `Handshake state missing state parameter [session_id: ${session_id}]`);
		return Result.err(STATE_CORRUPTED);
	}
	if (!data.nonce || type(data.nonce) !== "string") {
		deps.log("error", `Handshake state missing nonce [session_id: ${session_id}]`);
		return Result.err(STATE_CORRUPTED);
	}

	// Enforce mandatory exp and iat claims
	if (data.exp === null || type(data.exp) !== "int") {
		deps.log("error", `Handshake state missing or invalid 'exp' [session_id: ${session_id}]`);
		return Result.err(STATE_CORRUPTED);
	}
	if (data.iat === null || type(data.iat) !== "int") {
		deps.log("error", `Handshake state missing or invalid 'iat' [session_id: ${session_id}]`);
		return Result.err(STATE_CORRUPTED);
	}

	let now = deps.clock.time();

	if (data.exp < (now - clock_tolerance)) {
		deps.log("warn", `Handshake state expired [session_id: ${session_id}]`);
		return Result.err(HANDSHAKE_EXPIRED);
	}

	if (data.iat > (now + clock_tolerance)) {
		deps.log("warn", `Handshake state not yet valid [session_id: ${session_id}]`);
		return Result.err(HANDSHAKE_NOT_YET_VALID);
	}

	deps.log("info", `Handshake state successfully validated [session_id: ${session_id}]`);

	return Result.ok(data);
};
