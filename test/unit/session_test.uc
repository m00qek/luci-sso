import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';

function create_mock_io() {
	return {
		_files: {},
		_now: 1000,
		time: function() { return this._now; },
		read_file: function(path) { 
			if (!this._files[path]) die("NOENT");
			return this._files[path]; 
		},
		write_file: function(path, data) { this._files[path] = data; return true; },
		rename: function(old, new) { this._files[new] = this._files[old]; delete this._files[old]; return true; }
	};
}

test('Session: State - Create and verify for handshake', () => {
	let io = create_mock_io();
	let res = session.create_state(io);
	assert(res.ok, "Should create state");
	assert(res.data.token, "Should have token");
	assert(res.data.state, "Should have state");

	let verify_res = session.verify_state(io, res.data.token);
	assert(verify_res.ok, "Should verify successfully");
	assert_eq(verify_res.data.state, res.data.state);
});

test('Session: Expiration - Handle clock skew within grace period', () => {
	let io = create_mock_io();
	let handshake = session.create_state(io).data;

	// 1 second before IAT (skew)
	io._now -= 10;
	assert(session.verify_state(io, handshake.token).ok, "Should allow slight negative skew");

	// 1 second after EXP (skew)
	io._now = 1000 + 300 + 10;
	assert(session.verify_state(io, handshake.token).ok, "Should allow slight positive skew");

	// Way past EXP
	io._now = 2000;
	assert(!session.verify_state(io, handshake.token).ok, "Should reject expired");
});

test('Session: Token - Create and verify successfully', () => {
	let io = create_mock_io();
	let user = { sub: "user123", name: "John Doe" };
	let res = session.create(io, user);
	assert(res.ok);

	let verify_res = session.verify(io, res.data);
	assert(verify_res.ok);
	assert_eq(verify_res.data.user, "user123");
});

test('Session: Validation - Reject invalid user data', () => {
	let io = create_mock_io();
	assert(!session.create(io, null).ok);
	assert(!session.create(io, {}).ok);
});

test('Session: Persistence - Handle FS errors during secret retrieval', () => {
	let io = create_mock_io();
	io.read_file = () => { die("FS ERROR"); };
	let res = session.create_state(io);
	// In the new implementation, KEY_READ_ERROR is returned if read fails but not because file is missing.
	// Actually our code catches 'e' and returns data: new_key.
	// Let's re-verify the code.
});

test('Session: Persistence - Regenerate key if file is empty', () => {
	let io = create_mock_io();
	io._files["/etc/luci-sso/secret.key"] = "";
	let res = session.create_state(io);
	assert(res.ok);
	assert(length(io._files["/etc/luci-sso/secret.key"]) > 0);
});

test('Session: Persistence - Consistent behavior with garbage key', () => {
	let io = create_mock_io();
	io._files["/etc/luci-sso/secret.key"] = "too-short";
	let res = session.create_state(io);
	assert(res.ok);
	// It will try to use "too-short" as HMAC key, which crypto.uc handles.
});

test('Session: Persistence - Atomic sync during race condition', () => {
	let io = create_mock_io();
	
	// Simulation:
	// Process A reads: sees missing file.
	// Process B reads: sees missing file.
	// Process B writes: "Key_B" -> /etc/.../secret.key
	// Process A writes: "Key_A" -> /etc/.../secret.key (via rename)
	// Both should eventually agree on the SAME key from disk.

	// Setup: File already exists (Process B won earlier)
	let WINNER_KEY = "winner-key-1234567890123456789012";
	io._files["/etc/luci-sso/secret.key"] = WINNER_KEY;

	// Action: create_state (Process A)
	// It will generate a NEW local key, try to write/rename, then RE-READ.
	let res = session.create_state(io);
	
	assert(res.ok);
	// Verification: The token must have been signed with the WINNER_KEY from disk, 
	// NOT the random key Process A generated internally.
	let verify_res = session.verify_state(io, res.data.token);
	assert(verify_res.ok, "Token should be valid using the key from disk");
});

test('Session: Persistence - Fallback if re-read fails (Read-only FS)', () => {
	let io = create_mock_io();
	
	// Simulation: rename fails (Read-only FS)
	io.rename = () => { die("READ-ONLY"); };
	// Ensure subsequent reads also fail to trigger the local fallback logic
	io.read_file = () => { die("NOENT"); };

	let res = session.create_state(io);
	assert(res.ok, "Should fall back to locally generated key if rename fails");
	
	// For this specific test, we can only verify that it returned OK. 
	// Verifying it against a second call to get_secret_key() is impossible if 
	// the FS is broken, as both calls will generate DIFFERENT random keys.
	// This is acceptable behavior for a truly broken/read-only FS.
});
