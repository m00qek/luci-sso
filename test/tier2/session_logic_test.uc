import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';

test('session: logic - handshake lifecycle (creation, validation, atomic consumption)', () => {
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

test('session: logic - handle corrupted handshake files', () => {
	let factory = mock.create();
	let handle = "corrupted-handle";
	let path = `/var/run/luci-sso/handshake_${handle}.json`;
	
	factory.with_files({ [path]: "{ invalid json !!! }" }, (io) => {
		let res = session.verify_state(io, handle, 300);
		assert(!res.ok);
		assert_eq(res.error, "STATE_CORRUPTED");
	});
});

test('session: logic - enforce clock tolerance boundaries', () => {
	let factory = mock.create();
	let now = 1516239022;
	
	factory.with_env({}, (io) => {
		let handshake = {
			state: "s",
			nonce: "n",
			code_verifier: "verifier-verifier-verifier-verifier-verifier-verifier",
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

test('session: logic - reject malformed state handles', () => {
	let factory = mock.create();
	factory.with_env({}, (io) => {
		let res = session.verify_state(io, "../evil", 300);
		assert_eq(res.error, "INVALID_HANDLE_FORMAT");
	});
});

test('session: logic - concurrent verify_state race rejection', () => {
	let factory = mock.create();
	let handle = "race-handle";
	let path = `/var/run/luci-sso/handshake_${handle}.json`;
	let data = { state: "s", exp: 2000000000 };

	// 1. Setup the "consumed" file as if another process just renamed it
	factory.with_files({ [`${path}.consumed`]: sprintf("%J", data) }, (io) => {
		// Mock rename to fail (simulating race lost)
		io.rename = () => false; 
		
		let res = session.verify_state(io, handle, 300);
		assert(!res.ok, "Should NOT recover state from .consumed if rename failed (Strict One-Time Use)");
		assert_eq(res.error, "STATE_NOT_FOUND");
	});
});

test('session: logic - cleanup of abandoned handshakes', () => {
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

test('session: logic - secret key persistence (atomic race resilience)', () => {
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

test('session: logic - read-only FS resilience', () => {
	let factory = mock.create().with_read_only();
	factory.with_env({}, (io) => {
		// Should FAIL if it cannot persist the key
		let res = session.get_secret_key(io);
		assert(!res.ok);
		assert_eq(res.error, "SYSTEM_KEY_UNAVAILABLE");
	});
});

test('session: logic - secret key lock collision fallback', () => {
	let factory = mock.create();
	let key_path = "/etc/luci-sso/secret.key";

	// Scenario A: Lock held, but key eventually appears (concurrent success)
	factory.with_env({}, (io) => {
		let call_count = 0;
		io.mkdir = () => false; // Lock collision
		io.read_file = (path) => {
			if (path == key_path) {
				call_count++;
				// First call (check) fails, second call (after lock fail) succeeds
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
		assert(!res.ok, "Should fail if lock is held and key never appears");
		assert_eq(res.error, "SYSTEM_KEY_UNAVAILABLE");
	});
});

test('session: logic - explicit state consumption (cleanup)', () => {
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

test('session: logic - atomic handshake state creation', () => {
	let factory = mock.create();
	
	let history = factory.with_env({}).spy((io) => {
		let res = session.create_state(io);
		assert(res.ok, `create_state failed: ${res.error}`);
	});

	let operations = history.all();

	// Find the write operation
	let write_op = null;
	let write_idx = -1;
	for (let i = 0; i < length(operations); i++) {
		if (operations[i].type == "write_file") {
			write_op = operations[i];
			write_idx = i;
			break;
		}
	}

	assert(write_op, `Should have performed a write_file operation. Ops: ${sprintf("%J", operations)}`);
	assert(index(write_op.args[0], ".tmp") > 0, `Should write to temporary file first. Got: ${write_op.args[0]}`);

	let chmod_op = operations[write_idx + 1];
	assert(chmod_op && chmod_op.type == "chmod", "Should have performed chmod after write");
	assert_eq(chmod_op.args[0], write_op.args[0], "chmod should target the tmp file");
	assert_eq(chmod_op.args[1], 0600, "chmod should set 0600");

	let rename_op = operations[write_idx + 2];
	assert(rename_op && rename_op.type == "rename", "Should have performed rename after chmod");
	assert_eq(rename_op.args[0], write_op.args[0], "rename should move from the tmp file");
	assert(index(rename_op.args[1], ".tmp") == -1, `Target path should not be temporary. Got: ${rename_op.args[1]}`);
});

test('session: logic - detect CSPRNG failure during secret key generation (B1)', () => {
	let factory = mock.create();
	global.TESTING_RANDOM_FAIL = true;
	
	factory.with_env({}, (io) => {
		let res = session.get_secret_key(io);
		assert(!res.ok, "Should fail when random() returns null");
		assert_eq(res.error, "CRYPTO_SYSTEM_FAILURE");
	});
	
	global.TESTING_RANDOM_FAIL = false;
});

test('session: logic - detect CSPRNG failure during handshake creation (B2)', () => {
	let factory = mock.create();
	global.TESTING_RANDOM_FAIL = true;
	
	factory.with_env({}, (io) => {
		let res = session.create_state(io);
		assert(!res.ok, "Should fail when random() returns null");
		assert_eq(res.error, "CRYPTO_SYSTEM_FAILURE");
	});
	
	global.TESTING_RANDOM_FAIL = false;
});

// W1: Unchecked io.rename in get_secret_key
test('session: get_secret_key - W1 rename failure regression', () => {
	// Mock IO where rename fails (manual override)
	mock.create()
		.with_files({
			"/etc/luci-sso/secret.key": null, // Key does not exist
			"/etc/luci-sso": { ".type": "directory" }
		})
		.spy((io) => {
			// Manually inject a failing rename
			io.rename = () => false;

			let res = session.get_secret_key(io);
			
			assert(!res.ok, "W1: get_secret_key MUST fail if atomic rename fails");
			assert_eq(res.error, "SYSTEM_KEY_WRITE_FAILED", "W1: Expected error code for rename failure");
		});
});
