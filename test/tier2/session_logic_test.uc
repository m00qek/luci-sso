import { it, assert, truthy } from 'utest';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';
import * as native from 'luci_sso.native';

it('session: logic - handshake lifecycle (creation, validation, atomic consumption)', () => {
	let factory = mock.create();
	
	factory.with_env({}, (io) => {
		// 1. Create
		let state_res = session.create_state(io);
		assert.match(truthy(), state_res.ok);
		let handshake = state_res.data;
		assert.match(truthy(), handshake.token);
		
		// 2. Verify & Consume (Atomic)
		let verify_res = session.verify_state(io, handshake.token, 300);
		assert.match(truthy(), verify_res.ok);
		assert.match(handshake.state, verify_res.data.state);

		// 3. Replay Attempt (Must fail)
		let replay_res = session.verify_state(io, handshake.token, 300);
		assert.match(truthy(), !replay_res.ok);
		assert.match("STATE_NOT_FOUND", replay_res.error);
	});
});

it('session: logic - handle corrupted handshake files', () => {
	let factory = mock.create();
	let handle = "corrupted-handle";
	let path = `/var/run/luci-sso/handshake_${handle}.json`;
	
	factory.with_files({ [path]: "{ invalid json !!! }" }, (io) => {
		let res = session.verify_state(io, handle, 300);
		assert.match(truthy(), !res.ok);
		assert.match("STATE_CORRUPTED", res.error);
	});
});

it('session: logic - enforce clock tolerance boundaries', () => {
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
		assert.match(truthy(), !res.ok);
		assert.match("HANDSHAKE_EXPIRED", res.error);
	});
});

it('session: logic - reject malformed state handles', () => {
	let factory = mock.create();
	factory.with_env({}, (io) => {
		let res = session.verify_state(io, "../evil", 300);
		assert.match("MALFORMED_STATE_COOKIE", res.error);
	});
});

it('session: logic - concurrent verify_state race rejection', () => {
	let factory = mock.create();
	let handle = "race-handle";
	let path = `/var/run/luci-sso/handshake_${handle}.json`;
	let data = { state: "s", exp: 2000000000 };

	// 1. Setup the "consumed" file as if another process just renamed it
	factory.with_files({ [`${path}.consumed`]: sprintf("%J", data) }, (io) => {
		// Mock rename to fail (simulating race lost)
		io.rename = () => false; 
		
		let res = session.verify_state(io, handle, 300);
		assert.match(truthy(), !res.ok, "Should NOT recover state from .consumed if rename failed (Strict One-Time Use)");
		assert.match("STATE_NOT_FOUND", res.error);
	});
});

it('session: logic - cleanup of abandoned handshakes', () => {
	let factory = mock.create();
	let now = 1516239022;
	let old_path = "/var/run/luci-sso/handshake_old.json";
	let new_path = "/var/run/luci-sso/handshake_new.json";
	let other_path = "/var/run/luci-sso/important.txt";

	factory.with_files({
		[old_path]: { ".type": "file", "data": "{}", ".mtime": now - 1000 },
		[new_path]: { ".type": "file", "data": "{}", ".mtime": now },
		[other_path]: "keep me"
	}, (io) => {
		// Advance mock clock to match the 'now' we used for mtime
		io.__state__.now = now;

		let reap_res = session.reap_stale_handshakes(io, 300);
		assert.match(truthy(), reap_res.ok);
		assert.match(1, reap_res.data, "Should report 1 file reaped");
		
		assert.match(truthy(), !io.read_file(old_path), "Old handshake should be reaped");
		assert.match(truthy(), io.read_file(new_path), "Recent handshake should remain");
		assert.match(truthy(), io.read_file(other_path), "Unrelated files should be ignored");
	});
});

it('session: logic - stale secret key lock self-healing (Audit #104)', () => {
	let factory = mock.create();
	let lock_path = "/etc/luci-sso/secret.key.lock";

	factory.with_env({}, (io) => {
		// Capture the base time
		let base_now = io.time();

		// Setup the lock with a stale mtime using the new mock capability
		let history = factory.using(io).with_files({
			[lock_path]: { ".type": "directory", ".mtime": base_now - 31 }
		}).spy((spying_io) => {
			let res = session.get_secret_key(spying_io);
			assert.match(truthy(), res.ok, "Should succeed by self-healing the stale lock");
			assert.match(truthy(), length(res.data) == 32, "Should return a valid 32-byte key");
		});

		// Verify warning log was emitted
		assert.match(truthy(), history.called("log", "warn", "Stale secret key lock detected; performing self-healing cleanup"), "Should log a warning about stale lock");

		// Verify lock was removed and re-created
		assert.match(truthy(), history.called("remove", lock_path), "Should have removed the stale lock");
		assert.match(truthy(), history.called("mkdir", lock_path), "Should have re-acquired the lock");
	});
});

it('session: logic - secret key persistence (atomic race resilience)', () => {
	let factory = mock.create();
	let key_path = "/etc/luci-sso/secret.key";

	factory.with_env({}, (io) => {
		// 1. Successive calls should return same key
		let res1 = session.get_secret_key(io);
		let res2 = session.get_secret_key(io);
		assert.match(res2.data, res1.data);
		assert.match(32, length(res1.data));
	});
});

it('session: logic - read-only FS resilience', () => {
	let factory = mock.create().with_read_only();
	factory.with_env({}, (io) => {
		// Should FAIL if it cannot persist the key
		let res = session.get_secret_key(io);
		assert.match(truthy(), !res.ok);
		assert.match("SYSTEM_KEY_UNAVAILABLE", res.error);
	});
});

it('session: logic - secret key lock collision fallback', () => {
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
		assert.match(truthy(), res.ok);
		assert.match("ANOTHER_PROCESS_KEY_012345678901", res.data, "Should recover key from concurrent process");
	});

	// Scenario B: Lock held, and key NEVER appears (concurrent failure/slowness)
	factory.with_env({}, (io) => {
		io.mkdir = () => false; // Lock collision
		io.read_file = () => null; // File missing

		let res = session.get_secret_key(io);
		assert.match(truthy(), !res.ok, "Should fail if lock is held and key never appears");
		assert.match("SYSTEM_KEY_UNAVAILABLE", res.error);
	});
});

it('session: logic - explicit state consumption (cleanup)', () => {
	let factory = mock.create();
	factory.with_env({}, (io) => {
		let state_res = session.create_state(io);
		let handle = state_res.data.token;
		let path = `/var/run/luci-sso/handshake_${handle}.json`;
		
		assert.match(truthy(), io.read_file(path), "Handshake file should exist");
		
		session.consume_state(io, handle);
		assert.match(truthy(), !io.read_file(path), "Handshake file should have been deleted");
	});
});

it('session: logic - atomic handshake state creation', () => {
	let factory = mock.create();
	
	let history = factory.with_env({}).spy((io) => {
		let res = session.create_state(io);
		assert.match(truthy(), res.ok, `create_state failed: ${res.error}`);
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

	assert.match(truthy(), write_op, `Should have performed a write_file operation. Ops: ${sprintf("%J", operations)}`);
	assert.match(truthy(), index(write_op.args[0], ".tmp") > 0, `Should write to temporary file first. Got: ${write_op.args[0]}`);

	let chmod_op = operations[write_idx + 1];
	assert.match(truthy(), chmod_op && chmod_op.type == "chmod", "Should have performed chmod after write");
	assert.match(write_op.args[0], chmod_op.args[0], "chmod should target the tmp file");
	assert.match(0600, chmod_op.args[1], "chmod should set 0600");

	let rename_op = operations[write_idx + 2];
	assert.match(truthy(), rename_op && rename_op.type == "rename", "Should have performed rename after chmod");
	assert.match(write_op.args[0], rename_op.args[0], "rename should move from the tmp file");
	assert.match(truthy(), index(rename_op.args[1], ".tmp") == -1, `Target path should not be temporary. Got: ${rename_op.args[1]}`);
});

it('session: logic - detect CSPRNG failure during secret key generation (B1)', () => {
    crypto.set_native({ ...native, random: () => null });
    
    let res = null;
    let err = null;
    try {
        mock.create().with_env({}, (io) => {
            res = session.get_secret_key(io);
        });
    } catch (e) {
        err = e;
    }
    crypto.set_native(null);
    if (err) die(err);

    assert.match(truthy(), !res.ok, "Should fail when random() returns null");
    assert.match("CRYPTO_INIT_FAILED", res.error);
});

it('session: logic - detect CSPRNG failure during handshake creation (B2)', () => {
    crypto.set_native({ ...native, random: () => null });

    let res = null;
    let err = null;
    try {
        mock.create().with_env({}, (io) => {
            res = session.create_state(io);
        });
    } catch (e) {
        err = e;
    }
    crypto.set_native(null);
    if (err) die(err);

    assert.match(truthy(), !res.ok, "Should fail when random() returns null");
    assert.match("CRYPTO_INIT_FAILED", res.error);
});

// W1: Unchecked io.rename in get_secret_key
it('session: get_secret_key - W1 rename failure regression', () => {
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
			
			assert.match(truthy(), !res.ok, "W1: get_secret_key MUST fail if atomic rename fails");
			assert.match("SYSTEM_KEY_WRITE_FAILED", res.error, "W1: Expected error code for rename failure");
		});
});
