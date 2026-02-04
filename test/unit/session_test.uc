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
	
	let result = session.create(io, user);
	assert(result.session, "Should create a token in .session property");
	let token = result.session;
	
	let v_result = session.verify(io, token);
	assert(!v_result.error, `Should verify successfully, got: ${v_result.error}`);
	assert_eq(v_result.session.user, "123");
	assert_eq(v_result.session.name, "Test User");
});

test('State: Create and verify', () => {
	let io = create_mock_io();
	
	let handshake = session.create_state(io);
	assert(handshake.token, "Should return signed token");
	assert(handshake.state, "Should return raw state");
	assert(handshake.nonce, "Should return raw nonce");
	assert(handshake.code_challenge, "Should return code_challenge");
	
	let result = session.verify_state(io, handshake.token);
	assert(!result.error, `Should verify state, got: ${result.error}`);
	assert_eq(result.payload.state, handshake.state);
	assert_eq(result.payload.nonce, handshake.nonce);
});

test('State: Clock Skew', () => {
	let io = create_mock_io();
	let handshake = session.create_state(io);
	let token = handshake.token;
	
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
	let res = session.create(io, { name: "Ghost" });
	assert_eq(res.error, "INVALID_USER_DATA", "Should return error if no identifier present");
});

test('Session: Handle FS errors during secret retrieval', () => {
	let io = create_mock_io();
	io.read_file = fail_read;
	
	let res = session.create(io, { sub: "123" });
	assert_eq(res.error, "SECRET_KEY_ERROR", "Should return SECRET_KEY_ERROR if secret cannot be read");
	
	let result = session.verify(io, "some.token.here");
	assert_eq(result.error, "INTERNAL_ERROR", "Should return INTERNAL_ERROR on verify if FS fails");
});