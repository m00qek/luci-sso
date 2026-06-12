import { describe, it, assert, truthy, has_length, falsy, mock } from 'utest';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';

const FIXED_NOW = 1516239022;

function make_clock(now) {
	return { time: () => now, sleep: () => null };
}

describe('session: logic', () => {
	it('handshake lifecycle (creation, validation, atomic consumption)', () => {
		mock.inject('fs', {}, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(FIXED_NOW) };

			let state_res = session.create_state(deps);
			assert.match(truthy(), state_res.ok);
			let handshake = state_res.data;
			assert.match(truthy(), handshake.token);

			let verify_res = session.verify_state(deps, handshake.token, 300);
			assert.match(truthy(), verify_res.ok);
			assert.match(handshake.state, verify_res.data.state);

			let replay_res = session.verify_state(deps, handshake.token, 300);
			assert.match(falsy(), replay_res.ok);
			assert.match("STATE_NOT_FOUND", replay_res.error);
		});
	});

	it('handle corrupted handshake files', () => {
		let handle = "corrupted-handle";
		let path = `/var/run/luci-sso/handshake_${handle}.json`;

		mock.inject('fs', { data: { [path]: "{ invalid json !!! }" } }, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(FIXED_NOW) };
			let res = session.verify_state(deps, handle, 300);
			assert.match(falsy(), res.ok);
			assert.match("STATE_CORRUPTED", res.error);
		});
	});

	it('enforce clock tolerance boundaries', () => {
		let now = FIXED_NOW;

		mock.inject('fs', {}, (fs) => {
			let handshake = {
				state: "s",
				nonce: "n",
				code_verifier: "verifier-verifier-verifier-verifier-verifier-verifier",
				iat: now - 500,
				exp: now - 100
			};
			let handle = "expired-token";
			fs.writefile(`/var/run/luci-sso/handshake_${handle}.json`, sprintf("%J", handshake));

			let deps = { fs, log: () => null, clock: make_clock(now) };
			let res = session.verify_state(deps, handle, 10);
			assert.match(falsy(), res.ok);
			assert.match("HANDSHAKE_EXPIRED", res.error);
		});
	});

	it('reject malformed state handles', () => {
		mock.inject('fs', {}, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(FIXED_NOW) };
			let res = session.verify_state(deps, "../evil", 300);
			assert.match("MALFORMED_STATE_COOKIE", res.error);
		});
	});

	it('concurrent verify_state race rejection', () => {
		let handle = "race-handle";
		let path = `/var/run/luci-sso/handshake_${handle}.json`;
		let data = { state: "s", exp: 2000000000 };

		mock.inject('fs', {
			data: { [`${path}.consumed`]: sprintf("%J", data) },
			behavior: { rename: () => false }
		}, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(FIXED_NOW) };
			let res = session.verify_state(deps, handle, 300);
			assert.match(falsy(), res.ok, "Should NOT recover state from .consumed if rename failed (Strict One-Time Use)");
			assert.match("STATE_NOT_FOUND", res.error);
		});
	});

	it('cleanup of abandoned handshakes', () => {
		let now = FIXED_NOW;
		let old_path = "/var/run/luci-sso/handshake_old.json";
		let new_path = "/var/run/luci-sso/handshake_new.json";
		let other_path = "/var/run/luci-sso/important.txt";

		mock.inject('fs', {
			data: {
				[old_path]: "{}",
				[new_path]: "{}",
				[other_path]: "keep me"
			},
			behavior: {
				stat: (path) => {
					if (path === old_path) return { mtime: now - 1000 };
					if (path === new_path) return { mtime: now };
					return null;
				}
			}
		}, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(now) };
			let reap_res = session.reap_stale_handshakes(deps, 300);
			assert.match(truthy(), reap_res.ok);
			assert.match(1, reap_res.data, "Should report 1 file reaped");

			assert.match(falsy(), fs.readfile(old_path), "Old handshake should be reaped");
			assert.match(truthy(), fs.readfile(new_path), "Recent handshake should remain");
			assert.match(truthy(), fs.readfile(other_path), "Unrelated files should be ignored");
		});
	});

	it('stale secret key lock self-healing (Audit #104)', () => {
		let base_now = FIXED_NOW;
		const lock_path = "/etc/luci-sso/secret.key.lock";

		let log_calls = [];
		let log_fn = (level, msg) => push(log_calls, [level, msg]);

		mock.inject('fs', {
			behavior: {
				readfile: () => null,
				stat: (path) => {
					if (path === lock_path) return { mtime: base_now - 31 };
					return null;
				},
				mkdir: (() => {
					let lock_calls = 0;
					return (path) => {
						if (path === lock_path) {
							lock_calls++;
							return lock_calls > 1;
						}
						return true;
					};
				})()
			}
		}, (fs) => {
			let deps = { fs, log: log_fn, clock: make_clock(base_now) };
			let res = session.get_secret_key(deps);
			assert.match(truthy(), res.ok, "Should succeed by self-healing the stale lock");
			assert.match(has_length(32), res.data, "Should return a valid 32-byte key");

			let warn_found = false;
			for (let e in log_calls) if (e[0] === "warn" && e[1] === "Stale secret key lock detected; performing self-healing cleanup") warn_found = true;
			assert.match(truthy(), warn_found, "Should log a warning about stale lock");

			let unlink_found = false;
			for (let call in fs.__utest__.calls.unlink) if (call[0] === lock_path) unlink_found = true;
			assert.match(truthy(), unlink_found, "Should have removed the stale lock");

			let mkdir_found = false;
			for (let call in fs.__utest__.calls.mkdir) if (call[0] === lock_path) mkdir_found = true;
			assert.match(truthy(), mkdir_found, "Should have re-acquired the lock");
		});
	});

	it('secret key persistence (atomic race resilience)', () => {
		mock.inject('fs', {}, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(FIXED_NOW) };
			let res1 = session.get_secret_key(deps);
			let res2 = session.get_secret_key(deps);
			assert.match(res2.data, res1.data);
			assert.match(32, length(res1.data));
		});
	});

	it('read-only FS resilience', () => {
		mock.inject('fs', {
			behavior: {
				readfile:  () => null,
				writefile: () => null,
				rename:    () => false,
				mkdir:     () => false,
				error:     () => "Read-only file system"
			}
		}, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(FIXED_NOW) };
			let res = session.get_secret_key(deps);
			assert.match(falsy(), res.ok);
			assert.match("SYSTEM_KEY_UNAVAILABLE", res.error);
		});
	});

	it('secret key lock collision fallback', () => {
		mock.inject('fs', {
			behavior: {
				mkdir: (path) => {
					if (path === "/etc/luci-sso/secret.key.lock") return false;
					return true;
				},
				readfile: (() => {
					let call_count = 0;
					return (path) => {
						if (path === "/etc/luci-sso/secret.key") {
							call_count++;
							return (call_count > 1) ? "ANOTHER_PROCESS_KEY_012345678901" : null;
						}
						return null;
					};
				})()
			}
		}, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(FIXED_NOW) };
			let res = session.get_secret_key(deps);
			assert.match(truthy(), res.ok);
			assert.match("ANOTHER_PROCESS_KEY_012345678901", res.data, "Should recover key from concurrent process");
		});

		mock.inject('fs', {
			behavior: {
				mkdir:    () => false,
				readfile: () => null
			}
		}, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(FIXED_NOW) };
			let res = session.get_secret_key(deps);
			assert.match(falsy(), res.ok, "Should fail if lock is held and key never appears");
			assert.match("SYSTEM_KEY_UNAVAILABLE", res.error);
		});
	});

	it('explicit state consumption (cleanup)', () => {
		mock.inject('fs', {}, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(FIXED_NOW) };
			let state_res = session.create_state(deps);
			let handle = state_res.data.token;
			let path = `/var/run/luci-sso/handshake_${handle}.json`;

			assert.match(truthy(), fs.readfile(path), "Handshake file should exist");

			session.consume_state(deps, handle);
			assert.match(falsy(), fs.readfile(path), "Handshake file should have been deleted");
		});
	});

	it('atomic handshake state creation', () => {
		mock.inject('fs', {}, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(FIXED_NOW) };
			let res = session.create_state(deps);
			assert.match(truthy(), res.ok, `create_state failed: ${res.error}`);

			let writefile_calls = fs.__utest__.calls.writefile || [];
			let chmod_calls     = fs.__utest__.calls.chmod     || [];
			let rename_calls    = fs.__utest__.calls.rename    || [];

			let write_op = length(writefile_calls) > 0 ? writefile_calls[0] : null;
			assert.match(truthy(), write_op, "Should have performed a writefile operation");
			assert.match(truthy(), index(write_op[0], ".tmp") > 0, `Should write to temporary file first. Got: ${write_op[0]}`);

			let chmod_op = length(chmod_calls) > 0 ? chmod_calls[0] : null;
			assert.match(truthy(), chmod_op, "Should have performed chmod after write");
			assert.match(write_op[0], chmod_op[0], "chmod should target the tmp file");
			assert.match(0600, chmod_op[1], "chmod should set 0600");

			let rename_op = length(rename_calls) > 0 ? rename_calls[0] : null;
			assert.match(truthy(), rename_op, "Should have performed rename after chmod");
			assert.match(write_op[0], rename_op[0], "rename should move from the tmp file");
			assert.match(-1, index(rename_op[1], ".tmp"), `Target path should not be temporary. Got: ${rename_op[1]}`);
		});
	});

	it('detect CSPRNG failure during secret key generation (B1)', () => {
		crypto.set_native({ ...native, random: () => null });

		let res = null;
		let err = null;
		try {
			mock.inject('fs', { behavior: { readfile: () => null } }, (fs) => {
				res = session.get_secret_key({ fs, log: () => null, clock: make_clock(FIXED_NOW) });
			});
		} catch (e) {
			err = e;
		}
		crypto.set_native(null);
		if (err) die(err);

		assert.match(falsy(), res.ok, "Should fail when random() returns null");
		assert.match("CRYPTO_INIT_FAILED", res.error);
	});

	it('detect CSPRNG failure during handshake creation (B2)', () => {
		crypto.set_native({ ...native, random: () => null });

		let res = null;
		let err = null;
		try {
			mock.inject('fs', {}, (fs) => {
				res = session.create_state({ fs, log: () => null, clock: make_clock(FIXED_NOW) });
			});
		} catch (e) {
			err = e;
		}
		crypto.set_native(null);
		if (err) die(err);

		assert.match(falsy(), res.ok, "Should fail when random() returns null");
		assert.match("CRYPTO_INIT_FAILED", res.error);
	});
});

describe('session: get_secret_key', () => {
	it('W1 rename failure regression', () => {
		mock.inject('fs', {
			data: { "/etc/luci-sso": "" },
			behavior: { readfile: () => null, rename: () => false }
		}, (fs) => {
			let deps = { fs, log: () => null, clock: make_clock(FIXED_NOW) };
			let res = session.get_secret_key(deps);
			assert.match(falsy(), res.ok, "W1: get_secret_key MUST fail if atomic rename fails");
			assert.match("SYSTEM_KEY_WRITE_FAILED", res.error, "W1: Expected error code for rename failure");
		});
	});
});
