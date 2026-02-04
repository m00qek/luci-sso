import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';

function create_mock_io() {
	return {
		_files: {},
		_now: 100000, 
		time: function() { return this._now; },
		read_file: function(path) { return this._files[path]; },
		write_file: function(path, data) { this._files[path] = data; return true; }
	};
}

function fail_read() {
	throw("Permission Denied");
}

test('Session: Create and verify', () => {
	let io = create_mock_io();
	let user = { sub: "123", name: "Test User" };
	
	let token = session.create(io, user);
	assert(token, "Should create a token");
	
	let result = session.verify(io, token);
	assert(!result.error, `Should verify successfully, got: ${result.error}`);
	assert_eq(result.session.user, "123");
	assert_eq(result.session.name, "Test User");
});

test('Session: Clock Skew (Expired but in grace period)', () => {
	let io = create_mock_io();
	let token = session.create(io, { sub: "123" });
	
	// Advance time to 1s past expiration (3600 + 1)
	io._now += 3601;
	
	// Default skew is 60s, so it should still be valid
	let result = session.verify(io, token);
	assert(!result.error, "Should be valid within 60s skew");
	
	// Advance past skew (61s past expiration)
	io._now += 60;
	result = session.verify(io, token);
	assert_eq(result.error, "SESSION_EXPIRED");
});

test('Session: Clock Skew (Future token within grace period)', () => {
	let io = create_mock_io();
	let token = session.create(io, { sub: "123" });
	
	// Move clock BACKWARDS 30s
	io._now -= 30;
	
	let result = session.verify(io, token);
	assert(!result.error, "Should allow 30s future drift within 60s skew");
	
	// Move clock back past skew (61s total)
	io._now -= 31;
	result = session.verify(io, token);
	assert_eq(result.error, "SESSION_NOT_YET_VALID");
});

test('State: Create and verify', () => {
	let io = create_mock_io();
	let state = "random-state";
	let verifier = "pkce-verifier";
	let nonce = "random-nonce";
	
	let token = session.create_state(io, state, verifier, nonce);
	assert(token, "Should create a state token");
	
	let result = session.verify_state(io, token);
	assert(!result.error, `Should verify state, got: ${result.error}`);
	assert_eq(result.payload.state, state);
	assert_eq(result.payload.code_verifier, verifier);
	assert_eq(result.payload.nonce, nonce);
});

test('State: Clock Skew', () => {
	let io = create_mock_io();
	let token = session.create_state(io, "s", "v", "n");
	
	// 1. Just expired (301s)
	io._now += 301;
	let result = session.verify_state(io, token);
	assert(!result.error, "State should allow 30s skew by default");

	// 2. Past skew (331s)
	io._now += 30;
	result = session.verify_state(io, token);
	assert_eq(result.error, "HANDSHAKE_EXPIRED");
});

test('Session: Reject invalid user data', () => {
	let io = create_mock_io();
	
	// Missing sub and email
	assert_eq(session.create(io, { name: "Ghost" }), null, "Should return null if no identifier present");
	assert_eq(session.create(io, {}), null, "Should return null for empty object");
	assert_eq(session.create(io, null), null, "Should return null for null input");
});

test('Session: Handle FS errors during secret retrieval', () => {
	let io = create_mock_io();
	io.read_file = fail_read;
	
	let token = session.create(io, { sub: "123" });
	assert_eq(token, null, "Should return null if secret cannot be read due to error");
	
	let result = session.verify(io, "some.token.here");
	assert_eq(result.error, "INTERNAL_ERROR", "Should return INTERNAL_ERROR on verify if FS fails");
});
