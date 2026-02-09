import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

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