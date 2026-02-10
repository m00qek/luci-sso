import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';

test('Session: Logic - Handshake lifecycle (Creation, Validation, Atomic Consumption)', () => {
	let factory = mock.create();
	
	factory.with_env({}, (io) => {
		// 1. Create
		let state_res = session.create_state(io);
		assert(state_res.ok);
		let handshake = state_res.data;
		assert(handshake.token);
		
		// 2. Verify & Consume (Atomic)
		let verify_res = session.verify_state(io, handshake.token, 300);
		assert(verify_res.ok);
		assert_eq(verify_res.data.state, handshake.state);

		// 3. Replay Attempt (Must fail)
		let replay_res = session.verify_state(io, handshake.token, 300);
		assert(!replay_res.ok);
		assert_eq(replay_res.error, "STATE_NOT_FOUND");
	});
});

test('Session: Logic - Handle corrupted handshake files', () => {
	let factory = mock.create();
	let handle = "corrupted-handle";
	let path = `/var/run/luci-sso/handshake_${handle}.json`;
	
	factory.with_files({ [path]: "{ invalid json !!! }" }, (io) => {
		let res = session.verify_state(io, handle, 300);
		assert(!res.ok);
		assert_eq(res.error, "STATE_CORRUPTED");
	});
});

test('Session: Logic - Enforce clock tolerance boundaries', () => {
	let factory = mock.create();
	let now = 1516239022;
	
	factory.with_env({}, (io) => {
		let handshake = {
			state: "s",
			iat: now - 500,
			exp: now - 100
		};
		let handle = "expired-token";
		io.write_file(`/var/run/luci-sso/handshake_${handle}.json`, sprintf("%J", handshake));
		
		// 1. Expired (beyond tolerance)
		let res = session.verify_state(io, handle, 10);
		assert(!res.ok);
		assert_eq(res.error, "HANDSHAKE_EXPIRED");
	});
});

test('Session: Logic - Reject malformed state handles', () => {
	let factory = mock.create();
	factory.with_env({}, (io) => {
		let res = session.verify_state(io, "../evil", 300);
		assert_eq(res.error, "INVALID_HANDLE_FORMAT");
	});
});

test('Session: Logic - Concurrent verify_state race resilience', () => {
	let factory = mock.create();
	let handle = "race-handle";
	let path = `/var/run/luci-sso/handshake_${handle}.json`;
	let data = { state: "s", exp: 2000000000 };

	// 1. Setup the "consumed" file as if another process just renamed it
	factory.with_files({ [`${path}.consumed`]: sprintf("%J", data) }, (io) => {
		// Mock rename to fail (simulating race lost)
		io.rename = () => false; 
		
		let res = session.verify_state(io, handle, 300);
		assert(res.ok, "Should recover state from .consumed if rename failed but file exists");
	});
});

test('Session: Logic - Cleanup of abandoned handshakes', () => {
	let factory = mock.create();
	let now = 1516239022;
	let old_path = "/var/run/luci-sso/handshake_old.json";
	let new_path = "/var/run/luci-sso/handshake_new.json";
	let other_path = "/var/run/luci-sso/important.txt";

	factory.with_files({
		[old_path]: "{}",
		[new_path]: "{}",
		[other_path]: "keep me"
	}, (io) => {
		// Custom stat mock for timing
		io.stat = (path) => {
			if (index(path, "old") > 0) return { mtime: now - 1000 };
			return { mtime: now };
		};

		session.reap_stale_handshakes(io, 300);
		
		assert(!io.read_file(old_path), "Old handshake should be reaped");
		assert(io.read_file(new_path), "Recent handshake should remain");
		assert(io.read_file(other_path), "Unrelated files should be ignored");
	});
});

test('Session: Logic - Secret Key Persistence (Atomic Race Resilience)', () => {
	let factory = mock.create();
	let key_path = "/etc/luci-sso/secret.key";

	factory.with_env({}, (io) => {
		// 1. Successive calls should return same key
		let res1 = session.get_secret_key(io);
		let res2 = session.get_secret_key(io);
		assert_eq(res1.data, res2.data);
		assert_eq(length(res1.data), 32);
	});
});

test('Session: Logic - Read-only FS Resilience', () => {
	let factory = mock.create().with_read_only();
	factory.with_env({}, (io) => {
		// Should still return a temporary key if generation fails
		let res = session.get_secret_key(io);
		assert(res.ok);
		assert_eq(length(res.data), 32);
	});
});

test('Session: Logic - Secret Key Lock Collision Fallback', () => {
	let factory = mock.create();
	let key_path = "/etc/luci-sso/secret.key";

	// Scenario A: Lock held, but key eventually appears (concurrent success)
	factory.with_env({}, (io) => {
		let call_count = 0;
		io.mkdir = () => false; // Lock collision
		io.read_file = (path) => {
			if (path == key_path) {
				call_count++;
				// First call (check) fails, second call (fallback) succeeds
				return (call_count > 1) ? "ANOTHER_PROCESS_KEY_012345678901" : null;
			}
			return null;
		};

		let res = session.get_secret_key(io);
		assert(res.ok);
		assert_eq(res.data, "ANOTHER_PROCESS_KEY_012345678901", "Should recover key from concurrent process");
	});

	// Scenario B: Lock held, and key NEVER appears (concurrent failure/slowness)
	factory.with_env({}, (io) => {
		io.mkdir = () => false; // Lock collision
		io.read_file = () => null; // File missing

		let res = session.get_secret_key(io);
		assert(res.ok);
		assert_eq(length(res.data), 32, "Should fallback to temporary random key on collision failure");
	});
});

test('Session: Logic - Explicit state consumption (Cleanup)', () => {
	let factory = mock.create();
	factory.with_env({}, (io) => {
		let state_res = session.create_state(io);
		let handle = state_res.data.token;
		let path = `/var/run/luci-sso/handshake_${handle}.json`;
		
		assert(io.read_file(path), "Handshake file should exist");
		
		session.consume_state(io, handle);
		assert(!io.read_file(path), "Handshake file should have been deleted");
	});
});
