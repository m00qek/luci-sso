"use strict";

import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as Result from 'luci_sso.result';
import * as common from 'luci_sso.session.common';
import { CRYPTO_INIT_FAILED, STATE_SAVE_FAILED, MALFORMED_STATE_COOKIE, STATE_NOT_FOUND, STATE_CORRUPTED, HANDSHAKE_EXPIRED, HANDSHAKE_NOT_YET_VALID, HANDSHAKE_CAPACITY_EXCEEDED, STATE_PARAMETER_MISMATCH } from 'luci_sso.errors';

/**
 * Handshake lifecycle management (OIDC transient state).
 */

/**
 * Deletes handshake files whose age exceeds `max_age` seconds and returns how
 * many were removed. Age is measured from the file's mtime, which is the
 * handshake's `iat`: files are written once and never modified.
 * @private
 */
function _reap_older_than(deps, files, max_age) {
	let now = deps.clock.time();
	let reaped = 0;
	for (let f in files) {
		if (!match(f, /^handshake_[A-Za-z0-9_-]+\.json$/)) continue;
		let path = `${common.HANDSHAKE_DIR}/${f}`;
		let st = deps.fs.stat(path);
		if (st && st.mtime && (now - st.mtime) > max_age) {
			try {
				if (deps.fs.unlink(path)) reaped++;
			} catch (e) {}
		}
	}
	return reaped;
}

/**
 * Removes handshake files older than the duration.
 * @param {*} deps Service dependencies: `deps.fs` and `deps.clock`.
 * @param {int} clock_tolerance Extra grace seconds added beyond the handshake TTL before a file is reaped.
 * @returns {Result}
 */
export function reap(deps, clock_tolerance) {
	if (type(clock_tolerance) !== "int") die("CONTRACT_VIOLATION: reap expects mandatory integer clock_tolerance");

	let files = deps.fs.lsdir(common.HANDSHAKE_DIR);
	if (!files) return Result.ok(0);

	// A slightly larger grace period than duration + tolerance.
	return Result.ok(_reap_older_than(deps, files,
		common.HANDSHAKE_DURATION + clock_tolerance + common.REAP_GRACE_PERIOD));
};

/**
 * Creates an opaque handshake state on the server.
 *
 * At most LIMIT_PENDING_HANDSHAKES may exist. At the cap, handshakes that can
 * no longer be completed (past `exp` + clock_tolerance, which verify would
 * reject) are removed to make room. A handshake that could still be completed
 * is never removed: when every slot is live, the new login is refused with
 * HANDSHAKE_CAPACITY_EXCEEDED and the users already at the IdP are unaffected.
 *
 * `return_to`, when given, is stored with the handshake and returned by
 * verify. The caller validates it (encoding.return_path); it never leaves
 * the router.
 *
 * @param {*} deps Service dependencies: `deps.fs`, `deps.clock`, `deps.native`, `deps.log`.
 * @param {int} clock_tolerance Clock skew tolerance in seconds, as passed to verify.
 * @param {?string} [return_to] The LuCI page to open after the login, or null.
 * @returns {Result}
 */
export function create(deps, clock_tolerance, return_to) {
	if (type(clock_tolerance) !== "int") die("CONTRACT_VIOLATION: create expects mandatory integer clock_tolerance");
	if (return_to != null && type(return_to) !== "string") die("CONTRACT_VIOLATION: create expects a string or null return_to");

	common.ensure_handshake_dir(deps);

	let files = deps.fs.lsdir(common.HANDSHAKE_DIR) || [];
	let count = 0;
	for (let f in files) {
		if (match(f, /^handshake_.*\.json$/)) count++;
	}

	if (count >= common.LIMIT_PENDING_HANDSHAKES) {
		let freed = _reap_older_than(deps, files, common.HANDSHAKE_DURATION + clock_tolerance);
		if (count - freed >= common.LIMIT_PENDING_HANDSHAKES) {
			deps.log("warn", `Handshake capacity reached (${count - freed} pending, limit ${common.LIMIT_PENDING_HANDSHAKES}); refusing new login`);
			return Result.err(HANDSHAKE_CAPACITY_EXCEEDED);
		}
		deps.log("info", `Handshake capacity reached; removed ${freed} expired handshakes`);
	}

	let res_p = crypto.pkce_pair(deps.native);
	let res_s = crypto.random(deps.native, 16);
	let res_n = crypto.random(deps.native, 16);
	let res_h = crypto.random(deps.native, 32);

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
		id: crypto.safe_id(deps.native, handle), // Correlation ID for logs
		state: state,
		code_verifier: pkce.verifier,
		nonce: nonce,
		iat: now,
		exp: now + common.HANDSHAKE_DURATION
	};
	if (return_to != null)
		data.return_to = return_to;

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
 * @param {*} deps Service dependencies: `deps.fs`.
 * @param {string} handle Opaque base64url handle from the client cookie.
 * @returns {void}
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
 * Verifies a handshake against the callback's `state`, then consumes it.
 *
 * Handshake files are written once, by atomic rename, and never modified, so
 * the file can be read and checked BEFORE it is claimed. Only a request that
 * presents the right `state` for a live handshake consumes it. A cross-site
 * request with the victim's cookie but a wrong `state` is rejected and leaves
 * the pending login intact.
 *
 * Order: read → validate contents → compare state (constant time) → check the
 * time window → claim with an atomic rename to `.consumed`. The rename is the
 * single-winner step: of two callbacks racing with the right state, exactly
 * one succeeds and the other gets STATE_NOT_FOUND.
 *
 * - wrong state: STATE_PARAMETER_MISMATCH, the file is kept.
 * - corrupt, expired or not yet valid: the file is removed, and the matching
 *   error is returned.
 *
 * @param {*} deps Service dependencies: `deps.fs`, `deps.clock`, `deps.native`, `deps.log`.
 * @param {string} handle Opaque base64url handle from the client cookie.
 * @param {*} expected_state The `state` query parameter of the callback (untrusted).
 * @param {int} clock_tolerance Clock skew tolerance in seconds for `iat`/`exp` validation.
 * @returns {Result}
 */
export function verify(deps, handle, expected_state, clock_tolerance) {
	if (type(handle) !== "string") die("CONTRACT_VIOLATION: verify expects string handle");
	if (type(clock_tolerance) !== "int") die("CONTRACT_VIOLATION: verify expects mandatory integer clock_tolerance");

	// Ensure the handle is a safe filename (Base64URL only)
	if (!match(handle, /^[A-Za-z0-9_-]+$/)) {
		return Result.err(MALFORMED_STATE_COOKIE);
	}

	let path = `${common.HANDSHAKE_DIR}/handshake_${handle}.json`;
	let session_id = crypto.safe_id(deps.native, handle);

	// A handshake that fails validation will never be usable: drop it.
	let discard = () => { try { deps.fs.unlink(path); } catch (e) {} };

	let content = null;
	try {
		content = deps.fs.readfile(path);
	} catch (e) {
		content = null;
	}
	if (!content) {
		deps.log("error", `Handshake state not found or already consumed [session_id: ${session_id}]`);
		return Result.err(STATE_NOT_FOUND);
	}

	let res = encoding.safe_json(content);
	if (!res.ok) {
		deps.log("error", `Handshake state corrupted [session_id: ${session_id}]: ${res.details}`);
		discard();
		return Result.err(STATE_CORRUPTED);
	}
	let data = res.data;

	// Validate mandatory handshake fields on load
	let corrupt = null;
	if (!data.code_verifier || type(data.code_verifier) !== "string" || length(data.code_verifier) < 43 || length(data.code_verifier) > 128)
		corrupt = "missing or invalid PKCE verifier";
	else if (!data.state || type(data.state) !== "string")
		corrupt = "missing state parameter";
	else if (!data.nonce || type(data.nonce) !== "string")
		corrupt = "missing nonce";
	else if (data.exp === null || type(data.exp) !== "int")
		corrupt = "missing or invalid 'exp'";
	else if (data.iat === null || type(data.iat) !== "int")
		corrupt = "missing or invalid 'iat'";

	if (corrupt) {
		deps.log("error", `Handshake state ${corrupt} [session_id: ${session_id}]`);
		discard();
		return Result.err(STATE_CORRUPTED);
	}

	// Wrong state: this request did not start the flow. Keep the handshake so
	// the real callback can still complete it.
	if (type(expected_state) !== "string" || !crypto.constant_time_eq(data.state, expected_state)) {
		deps.log("warn", `Callback state does not match the handshake; handshake kept [session_id: ${session_id}]`);
		return Result.err(STATE_PARAMETER_MISMATCH);
	}

	let now = deps.clock.time();

	if (data.exp < (now - clock_tolerance)) {
		deps.log("warn", `Handshake state expired [session_id: ${session_id}]`);
		discard();
		return Result.err(HANDSHAKE_EXPIRED);
	}

	if (data.iat > (now + clock_tolerance)) {
		deps.log("warn", `Handshake state not yet valid [session_id: ${session_id}]`);
		discard();
		return Result.err(HANDSHAKE_NOT_YET_VALID);
	}

	// Claim: only one process can win the rename.
	let consume_path = `${path}.consumed`;
	let claimed = false;
	try {
		claimed = deps.fs.rename(path, consume_path);
	} catch (e) {
		claimed = false;
	}
	if (!claimed) {
		deps.log("error", `Handshake state already consumed [session_id: ${session_id}]`);
		return Result.err(STATE_NOT_FOUND);
	}
	try { deps.fs.unlink(consume_path); } catch (e) {}

	deps.log("info", `Handshake state successfully validated [session_id: ${session_id}]`);

	return Result.ok(data);
};
