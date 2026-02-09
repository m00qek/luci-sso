import { test, assert, assert_eq, when, then } from 'testing';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

// =============================================================================
// Tier 2: Session Management Logic (Platinum Suite)
// =============================================================================

const HANDSHAKE_DIR = "/var/run/luci-sso";

when("managing OIDC handshake state", () => {
	let mocked = mock.create();

	then("it should create a valid state file with unique identifiers", () => {
		let data = mocked.spy((io) => {
			let res = session.create_state(io);
			assert(res.ok);
			assert(length(res.data.state) >= 16);
			assert(length(res.data.nonce) >= 16);
			assert(length(res.data.token) >= 32);
		});

		// Verify side-effect: Exactly one state file created in /var/run/luci-sso
		let writes = 0;
		for (let entry in data.all()) {
			if (entry.type == "write_file") {
				assert(index(entry.args[0], HANDSHAKE_DIR + "/handshake_") == 0);
				writes++;
			}
		}
		assert_eq(writes, 1);
	});

	then("it should verify a valid state and then destroy it (atomic)", () => {
		let handle = "test-handle-123";
		let state_val = "correct-state";
		let state_data = { state: state_val, nonce: "n", verifier: "v", exp: 1516239999 };
		let path = HANDSHAKE_DIR + "/handshake_" + handle + ".json";

		mocked.with_files({ [path]: sprintf("%J", state_data) }, (io) => {
			let res = session.verify_state(io, handle, 300);
			assert(res.ok, "Verification should succeed");
			assert_eq(res.data.nonce, "n");

			// Verify side-effect: The file must be deleted immediately after verification
			assert_eq(io.read_file(path), null, "State file must be destroyed after use");
		});
	});

	then("it should handle corrupted JSON state files by deleting them", () => {
		let handle = "corrupted";
		let path = HANDSHAKE_DIR + "/handshake_" + handle + ".json";

		mocked.with_files({ [path]: "{" }, (io) => {
			let res = session.verify_state(io, handle, 300);
			assert(!res.ok);
			assert_eq(res.error, "STATE_CORRUPTED");
			assert_eq(io.read_file(path), null, "Corrupted file must be removed");
		});
	});

	then("it should enforce strict clock tolerance boundaries", () => {
		let now = 1516239022;
		let tolerance = 300;
		let handle = "boundary";
		let path = HANDSHAKE_DIR + "/handshake_" + handle + ".json";

		// 1. Exactly on the edge (Success)
		let valid_data = { exp: now - tolerance }; 
		mocked.with_files({ [path]: sprintf("%J", valid_data) }, (io) => {
			assert(session.verify_state(io, handle, tolerance).ok);
		});

		// 2. Just past the edge (Expired)
		let expired_data = { exp: now - tolerance - 1 };
		mocked.with_files({ [path]: sprintf("%J", expired_data) }, (io) => {
			let res = session.verify_state(io, handle, tolerance);
			assert(!res.ok);
			assert_eq(res.error, "HANDSHAKE_EXPIRED");
		});
	});

	then("it should reject state if the handle is malformed", () => {
		mocked.with_files({}, (io) => {
			assert(!session.verify_state(io, "../../etc/passwd", 300).ok);
		});
	});

	then("it should handle concurrent verify_state calls (race condition fallback)", () => {
		let handle = "race-handle";
		let state_data = { state: "s", nonce: "n", verifier: "v", exp: 1516239999 };
		let path = HANDSHAKE_DIR + "/handshake_" + handle + ".json";
		let consume_path = path + ".consumed";

		mocked.with_files({ [consume_path]: sprintf("%J", state_data) }, (io) => {
			// Simulate rename failure (because path doesn't exist, it's already consumed)
			io.rename = () => false;

			let res = session.verify_state(io, handle, 300);
			assert(res.ok, "Fallback to .consumed should succeed");
			assert_eq(res.data.state, "s");
			
			// Verify it still cleans up the consumed file
			assert_eq(io.read_file(consume_path), null, "Consumed file must be removed after fallback read");
		});
	});
});

when("reaping abandoned handshakes", () => {
	let mocked = mock.create();
	let now = 1516239022;

	then("it should remove old handshakes but leave unrelated files untouched", () => {
		let files = {
			"/var/run/luci-sso/handshake_old.json": "{}",
			"/var/run/luci-sso/important_data.json": "keep-me"
		};

		mocked.with_files(files, (io) => {
			// Mock stat to return specific mtimes
			let original_stat = io.stat;
			io.stat = (path) => {
				if (index(path, "old") > 0) return { mtime: now - 1000 };
				if (index(path, "important") > 0) return { mtime: now - 1000 };
				return original_stat(path);
			};

			session.reap_stale_handshakes(io, 300);
			
			assert_eq(io.read_file("/var/run/luci-sso/handshake_old.json"), null, "Old handshake should be reaped");
			assert_eq(io.read_file("/var/run/luci-sso/important_data.json"), "keep-me", "Unrelated file must be preserved");
		});
	});
});

test('LOGIC: Session - Secret Key Persistence (Atomic Race Resilience)', () => {
	let mocked = mock.create();
	let path = "/etc/luci-sso/secret.key";

	mocked.with_files({}, (io) => {
		// Simulate a race where rename fails (e.g. read-only FS or concurrent write)
		io.rename = () => { die("FS_ERROR"); };

		let res = session.get_secret_key(io);
		assert(res.ok);
		assert(length(res.data) == 32, "Should return a valid key even if save fails");
		
		// Subsequent call should still work (it will generate a new one if it couldn't save)
		let res2 = session.get_secret_key(io);
		assert(res2.ok);
	});
});

test('LOGIC: Session Persistence - Read-only FS Resilience', () => {
	let mocked = mock.create();
	
	let data = mocked.with_read_only((io) => {
		return mocked.using(io).spy((spying_io) => {
			let res = session.create_state(spying_io);
			assert(!res.ok);
			assert_eq(res.error, "STATE_SAVE_FAILED");
		});
	});

	// Platinum verification: Ensure the ACTUAL error was logged, not just a placeholder
	assert(data.called("log", "error"), "Should have logged the error");
	let found = false;
	for (let entry in data.all()) {
		if (entry.type == "log" && entry.args[0] == "error" && index(entry.args[1], "Read-only file system") > 0) {
			found = true;
			break;
		}
	}
	assert(found, "Log should contain the OS error");
});
