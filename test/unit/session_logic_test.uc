import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as h from 'unit.helpers';

const SECRET_PATH = "/etc/luci-sso/secret.key";

// =============================================================================
// Tier 2: Session Management Logic
// =============================================================================

test('LOGIC: Session State - Create & Verify', () => {
	let io = h.create_mock_io(1000);
	let res = session.create_state(io);
	assert(res.ok, "Should create handshake state");
	assert(res.data.token, "Should have state token");
	assert(res.data.state, "Should have CSRF state string");

	let verify_res = session.verify_state(io, res.data.token);
	assert(verify_res.ok, "Should verify state successfully");
	assert_eq(verify_res.data.state, res.data.state, "States should match");
});

test('LOGIC: Session - Expiration & Clock Skew', () => {
	let io = h.create_mock_io(1000);
	let handshake = session.create_state(io).data;

	// 1. Within Skew (Pass)
	io._now = 1000 + 300 + 5; // 5 seconds past expiration
	assert(session.verify_state(io, handshake.token).ok, "Should allow 5s skew");

	// 2. Past Skew (Fail)
	io._now = 1000 + 300 + 305; // 305 seconds past expiration
	let res = session.verify_state(io, handshake.token);
	assert_eq(res.error, "HANDSHAKE_EXPIRED");
});

test('LOGIC: Session Persistence - Atomic Sync (Race Condition)', () => {
	let io = h.create_mock_io(1000);
	
	// Simulation:
	// Process A and B both see no secret file.
	// Process B writes "WINNER-SECRET".
	// Process A generates "LOSER-SECRET", but its rename/write must result in using "WINNER-SECRET".
	
	let WINNER_SECRET = "winner-secret-32-bytes-long-1234";
	io._files[SECRET_PATH] = WINNER_SECRET;

	// Process A calls create_state
	let res = session.create_state(io);
	assert(res.ok);
	
	// Proves that the token returned to A is signed with B's secret (from disk)
	let verify_res = session.verify_state(io, res.data.token);
	assert(verify_res.ok, "Process A must use the secret already on disk");
});

test('LOGIC: Session Persistence - Read-only FS Resilience', () => {
	let io = h.create_mock_io(1000);
	
	// Simulation: rename fails (Read-only FS)
    io.rename = function() { die("EROFS: Read-only file system"); };
    // Ensure subsequent reads also fail
    io.read_file = function(path) { if (path == SECRET_PATH) die("NOENT"); return null; };

	let res = session.create_state(io);
	assert(res.ok, "Should fall back to ephemeral local key if FS is read-only");
    assert(res.data.token, "Should still return a usable token");
});

test('LOGIC: User Validation - Reject Malformed Data', () => {
	let io = h.create_mock_io(1000);
	assert_eq(session.create(io, null).error, "INVALID_USER_DATA");
	assert_eq(session.create(io, {}).error, "INVALID_USER_DATA");
});
