import { it, assert, truthy, mock } from 'utest';
import * as session from 'luci_sso.session';

const LOCK_PATH = "/etc/luci-sso/secret.key.lock";
const KEY_TMP_PATH = "/etc/luci-sso/secret.key.tmp";
const STALE_MTIME = 1000000000;
const NOW = 1516239022;

function make_stale_lock_behavior() {
	let mkdir_calls = 0;
	return {
		stat: (path) => {
			if (path === LOCK_PATH) return { mtime: STALE_MTIME };
			return null;
		},
		mkdir: (path) => {
			if (path === LOCK_PATH) {
				mkdir_calls++;
				return mkdir_calls > 1;
			}
			return true;
		}
	};
}

it('session: get_secret_key - reproduction of permanent lockout on stale lock', () => {
	mock.inject('fs', { behavior: make_stale_lock_behavior() }, (fs) => {
		let res = session.get_secret_key({ fs, log: () => null, clock: { time: () => NOW, sleep: () => null } });
		assert.match(truthy(), res.ok, "Should succeed with self-healing");
		assert.match(32, length(res.data), "Should return a 32-byte key");
	});
});

it('session: get_secret_key - self-healing log and cleanup verification', () => {
	let log_calls = [];

	mock.inject('fs', { behavior: make_stale_lock_behavior() }, (fs) => {
		let log = (level, msg) => push(log_calls, [level, msg]);
		session.get_secret_key({ fs, log, clock: { time: () => NOW, sleep: () => null } });

		let warn_found = false;
		for (let e in log_calls) {
			if (e[0] === "warn" && e[1] === "Stale secret key lock detected; performing self-healing cleanup")
				warn_found = true;
		}
		assert.match(truthy(), warn_found, "Should log self-healing event");

		let unlink_calls = fs.__utest__.calls.unlink || [];
		let lock_removed = false;
		for (let call in unlink_calls) {
			if (call[0] === LOCK_PATH) lock_removed = true;
		}
		assert.match(truthy(), lock_removed, "Should remove the stale lock");

		let write_calls = fs.__utest__.calls.writefile || [];
		let tmp_written = false;
		for (let call in write_calls) {
			if (call[0] === KEY_TMP_PATH) tmp_written = true;
		}
		assert.match(truthy(), tmp_written, "Should proceed with generation after healing");
	});
});
