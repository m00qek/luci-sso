import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';

function create_mock_io() {
	return {
		_files: {},
		_now: 1000,
		time: function() { return this._now; },
		read_file: function(path) { return this._files[path]; },
		write_file: function(path, data) { this._files[path] = data; return true; }
	};
}

test('Session JWS: Create and verify', () => {
	let io = create_mock_io();
	let user = { sub: "123", name: "Test User" };
	
	let token = session.create_session(io, user);
	assert(token, "Should create a JWS token");
	let parts = split(token, ".");
	assert_eq(length(parts), 3, "JWS should have 3 parts");

	let result = session.verify_session(io, token);
	assert(!result.error, `Should verify successfully, got: ${result.error}`);
	assert_eq(result.session.user, "123");
	assert_eq(result.session.name, "Test User");
});

test('Session JWS: Handle expiration', () => {
	let io = create_mock_io();
	let user = { sub: "123" };
	
	let token = session.create_session(io, user);
	
	// Advance time past 1 hour (3600s)
	io._now += 3601;
	
	let result = session.verify_session(io, token);
	assert_eq(result.error, "SESSION_EXPIRED", "Should reject expired session");
});

test('Session JWS: Reject tampered token', () => {
	let io = create_mock_io();
	let token = session.create_session(io, { sub: "123" });
	
	let parts = split(token, ".");
	let tampered = parts[0] + "." + parts[1] + "X" + "." + parts[2];
	let result = session.verify_session(io, tampered);
	assert_eq(result.error, "INVALID_SESSION", "Should reject tampered token");
});

test('Session JWS: Secret persistence', () => {
	let io = create_mock_io();
	let key = "existing-secret-key-existing-secret-key"; 
	io._files["/etc/luci-sso/secret.key"] = key;
	
	let token = session.create_session(io, { sub: "123" });
	let result = session.verify_session(io, token);
	assert(!result.error);
	assert_eq(io._files["/etc/luci-sso/secret.key"], key, "Should not overwrite existing key");
});