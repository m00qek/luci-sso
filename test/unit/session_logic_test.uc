import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as h from 'unit.helpers';

const SECRET_PATH = "/etc/luci-sso/secret.key";

// =============================================================================
// Tier 2: Session Management Logic
// =============================================================================

test('LOGIC: Session State - Create & Verify (Server-Side)', () => {
	let io = h.create_mock_io(1000);
	let res = session.create_state(io);
	assert(res.ok, "Should create handshake state");
	
	let handle = res.data.token;
	assert(match(handle, /^[A-Za-z0-9_-]+$/), "Handle should be safe Base64URL");
	assert(io._files[`/var/run/luci-sso/handshake_${handle}.json`], "State should be saved to disk");

	let verify_res = session.verify_state(io, handle);
	assert(verify_res.ok, "Should verify state successfully");
	assert_eq(verify_res.data.state, res.data.state, "States should match");
	
	// One-Time Use Verification
	assert(!io._files[`/var/run/luci-sso/handshake_${handle}.json`], "State file should be deleted after use");
	let second_attempt = session.verify_state(io, handle);
	assert_eq(second_attempt.error, "STATE_NOT_FOUND", "Handshake should be single-use");
});

test('TORTURE: Session - Corrupted State File', () => {
	let io = h.create_mock_io(1000);
	let handle = "malicious-handle";
	io._files[`/var/run/luci-sso/handshake_${handle}.json`] = "{ invalid json !!! }";
	
	let res = session.verify_state(io, handle);
	assert_eq(res.error, "STATE_CORRUPTED");
	assert(!io._files[`/var/run/luci-sso/handshake_${handle}.json`], "Corrupted file should be cleaned up");
});

test('SECURITY: Session - Path Traversal Protection', () => {
	let io = h.create_mock_io(1000);
	
	// 1. Directory Traversal
	let res = session.verify_state(io, "../../etc/shadow");
	assert_eq(res.error, "INVALID_HANDLE_FORMAT");

	// 2. Illegal characters
	res = session.verify_state(io, "handshake;rm -rf /");
	assert_eq(res.error, "INVALID_HANDLE_FORMAT");
});

test('TORTURE: Session - Directory Creation Failure', () => {
	let io = h.create_mock_io(1000);
	io.mkdir = function() { die("Permission denied"); };
	io.write_file = function() { die("Write failed"); };

	let res = session.create_state(io);
	assert_eq(res.error, "STATE_SAVE_FAILED");
});

test('LOGIC: Session - Handshake Reaper', () => {
	let io = h.create_mock_io(5000);
	
	// 1. Create a "Fresh" handshake (mtime = 5000)
	session.create_state(io);
	
	// 2. Manually inject a "Stale" handshake (mtime = 1000)
	let stale_path = "/var/run/luci-sso/handshake_stale-id.json";
	io._files[stale_path] = "{}";
	let original_stat = io.stat;
	io.stat = function(path) {
		if (path == stale_path) return { mtime: 1000 };
		return original_stat(path);
	};

	// 3. Run Reaper
	session.reap_stale_handshakes(io);

	// 4. Verify
	assert(!io._files[stale_path], "Stale handshake should be reaped");
	assert_eq(length(io.lsdir("/var/run/luci-sso")), 1, "Fresh handshake should remain");
});

test('LOGIC: Session - Expiration & Clock Skew', () => {
	let io = h.create_mock_io(1000);
	
	// 1. Within Skew (Pass)
	let h1 = session.create_state(io).data;
	io._now = 1000 + 300 + 5; // 5 seconds past expiration
	assert(session.verify_state(io, h1.token).ok, "Should allow 5s skew");

	// 2. Past Skew (Fail)
	io._now = 1000;
	let h2 = session.create_state(io).data;
	io._now = 1000 + 300 + 305; // 305 seconds past expiration
	let res = session.verify_state(io, h2.token);
	assert_eq(res.error, "HANDSHAKE_EXPIRED");
});

test('LOGIC: Session Persistence - Atomic Sync (Race Condition)', () => {
	let io = h.create_mock_io(1000);
	let WINNER_SECRET = "winner-secret-32-bytes-long-1234";
	io._files[SECRET_PATH] = WINNER_SECRET;

	// session.create internally uses the secret to sign JWS
	let res = session.create(io, { sub: "user1" });
	assert(res.ok);
	
	let verify_res = session.verify(io, res.data);
	assert(verify_res.ok, "Session must be verifiable using the secret on disk");
});

test('LOGIC: Session Persistence - Read-only FS Resilience', () => {
	let io = h.create_mock_io(1000);
	
	// Simulation: rename fails (Read-only FS)
    io.rename = function() { die("EROFS: Read-only file system"); };
    io.read_file = function(path) { if (path == SECRET_PATH) return null; return null; };

	let res = session.create(io, { sub: "user1" });
	assert(res.ok, "Should fall back to ephemeral local key if FS is read-only");
    assert(res.data, "Should still return a usable session token");
});

test('LOGIC: User Validation - Reject Malformed Data', () => {
	let io = h.create_mock_io(1000);
	assert_eq(session.create(io, null).error, "INVALID_USER_DATA");
	assert_eq(session.create(io, {}).error, "INVALID_USER_DATA");
});
