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

test('Session: Token - Create and verify successfully', () => {
	let io = create_mock_io();
	let user = { sub: "123", name: "Test User" };
	
	let result = session.create(io, user);
	assert(result.ok, "Should create a token");
	let token = result.data;
	
	let v_result = session.verify(io, token);
	assert(v_result.ok, `Should verify successfully, got: ${v_result.error}`);
	assert_eq(v_result.data.user, "123", "User sub should be correct");
	assert_eq(v_result.data.name, "Test User", "User name should be correct");
});

test('Session: Expiration - Handle clock skew within grace period', () => {
	let io = create_mock_io();
	let res = session.create(io, { sub: "123" });
	let token = res.data;
	
	// Advance time to 1s past expiration (3600 + 1)
	io._now += 3601;
	
	// Default skew is 60s, so it should still be valid
	let result = session.verify(io, token);
	assert(result.ok, "Should be valid within 60s skew");
	
	// Advance past skew (61s past expiration)
	io._now += 60;
	result = session.verify(io, token);
	assert_eq(result.error, "SESSION_EXPIRED", "Should reject after skew boundary");
});

test('Session: State - Create and verify for handshake', () => {
	let io = create_mock_io();
	
	let res = session.create_state(io);
	assert(res.ok, "Should create state");
	let handshake = res.data;
	assert(handshake.token, "Should return signed token");
	assert(handshake.state, "Should return raw state");
	
	let result = session.verify_state(io, handshake.token);
	assert(result.ok, `Should verify state, got: ${result.error}`);
	assert_eq(result.data.state, handshake.state, "States should match");
});

test('Session: Validation - Reject invalid user data', () => {
	let io = create_mock_io();
	
	// Missing sub and email
	let res = session.create(io, { name: "Ghost" });
	assert_eq(res.error, "INVALID_USER_DATA", "Should return error if no identifier present");
});

test('Session: Persistence - Handle FS errors during secret retrieval', () => {
	let io = create_mock_io();
	io.read_file = fail_read;
	
	let res = session.create(io, { sub: "123" });
	assert_eq(res.error, "KEY_READ_ERROR", "Should return error if FS fails");
});

test('Session: Persistence - Regenerate key if file is empty', () => {
	let io = create_mock_io();
	io._files["/etc/luci-sso/secret.key"] = ""; // Empty file
	
	let res = session.create(io, { sub: "123" });
	assert(res.ok, "Should regenerate key if file is empty");
	assert(length(io._files["/etc/luci-sso/secret.key"]) == 32, "Should have written new 32-byte key");
});

test('Session: Persistence - Consistent behavior with garbage key', () => {
	let io = create_mock_io();
	let garbage = "\x00\xff\x00\xaa";
	io._files["/etc/luci-sso/secret.key"] = garbage;
	
	let res = session.create(io, { sub: "123" });
	assert(res.ok, "Should accept any non-empty key");
	
	let verify_res = session.verify(io, res.data);
	assert(verify_res.ok, "Should be able to verify with the same garbage key");
});