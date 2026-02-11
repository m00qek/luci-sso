import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as oidc from 'luci_sso.oidc';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';

test('Session: Handshake - Atomic consumption ensures integrity', () => {
	let data = mock.create().with_files({}).spy((io) => {
		let res = session.create_state(io);
		let handle = res.data.token;
		session.verify_state(io, handle, 0);
	});

	assert(data.called("rename"), "Should have used rename for atomicity");
});

test('Session: Handshake - State is single-use only', () => {
	mock.create().with_files({}, (io) => {
		// 1. Create a state
		let res = session.create_state(io);
		let handle = res.data.token;

		// 2. Attempt 1: Should succeed
		let res_1 = session.verify_state(io, handle, 0);
		assert(res_1.ok, "First consumption should succeed");

		// 3. Attempt 2: Should fail
		let res_2 = session.verify_state(io, handle, 0);
		assert(!res_2.ok, "Second consumption should fail");

		// 4. Attempt 3: Should still fail
		let res_3 = session.verify_state(io, handle, 0);
		assert(!res_3.ok, "Third consumption should fail");
		assert_eq(res_3.error, "STATE_NOT_FOUND");
	});
});

test('Session: Handshake - Traversal attempts are rejected', () => {
	mock.create().with_files({}, (io) => {
		let res = session.verify_state(io, "../../../etc/passwd", 0);
		assert(!res.ok, "Should reject traversal attempt");
		assert_eq(res.error, "INVALID_HANDLE_FORMAT");
	});
});

test('Session: Handshake - Malformed JSON fails closed', () => {
	const handle = "malformed_handle";
	const path = `/var/run/luci-sso/handshake_${handle}.json`;

	mock.create().with_files({ [path]: "{ invalid: json" }, (io) => {
		let res = session.verify_state(io, handle, 0);
		assert(!res.ok, "Should fail on malformed JSON");
		assert_eq(res.error, "STATE_CORRUPTED");
	});
});

test('Session: Handshake - Filesystem error fails closed', () => {
	mock.create().with_files({}, (io) => {
		let res = session.create_state(io);
		let handle = res.data.token;

		// Derive a read-only reality
		mock.create().using(io).with_read_only((read_only_io) => {
			let res_fs = session.verify_state(read_only_io, handle, 0);
			assert(!res_fs.ok, "Should fail when rename is impossible");
			assert_eq(res_fs.error, "STATE_NOT_FOUND");
		});
	});
});

test('Security: Reject authorization URL generation without state (B1)', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.get_auth_url(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, { nonce: "n1234567890123456", code_challenge: "cc1" });
		assert(type(res) == "object" && !res.ok, "MUST return error object if state is missing");
		assert_eq(res.error, "MISSING_STATE_PARAMETER");
	});
});

test('Security: Reject authorization URL generation with weak state (B1)', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.get_auth_url(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, { state: "short", nonce: "n1234567890123456", code_challenge: "cc1" });
		assert(!res.ok, "MUST reject short state");
		assert_eq(res.error, "MISSING_STATE_PARAMETER");
	});
});

test('Security: Reject authorization URL generation without nonce (B1)', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.get_auth_url(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, { state: "s1234567890123456", code_challenge: "cc1" });
		assert(!res.ok, "MUST reject missing nonce");
		assert_eq(res.error, "MISSING_NONCE_PARAMETER");
	});
});

test('Security: Reject authorization URL generation without PKCE challenge (B1)', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.get_auth_url(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, { state: "s1234567890123456", nonce: "n1234567890123456" });
		assert(!res.ok, "MUST reject missing PKCE challenge");
		assert_eq(res.error, "MISSING_PKCE_CHALLENGE");
	});
});