import { it, assert, truthy } from 'utest';
import * as session from 'luci_sso.session';
import * as mock from 'mock';

function make_session_deps(io) {
	return {
		fs: {
			readfile:  (p)    => io.read_file(p),
			writefile: (p, d) => io.write_file(p, d),
			mkdir:     (p, m) => io.mkdir(p, m),
			unlink:    (p)    => io.remove(p),
			rename:    (o, n) => io.rename(o, n),
			stat:      (p)    => io.stat(p),
			chmod:     (p, m) => io.chmod(p, m),
			lsdir:     (p)    => io.lsdir(p),
			error:     ()     => io.fserror()
		},
		clock: { time: () => io.time(), sleep: (s) => io.sleep(s) },
		log: io.log
	};
}

// =============================================================================
// Tier 2: Handshake DoS Protection (Capacity Limits)
// =============================================================================

it('handshake: security - enforce hard capacity limit (DoS Protection)', () => {
	let factory = mock.create();

	factory.with_env({}, (io) => {
		// Mock secret key exists
		io.write_file("/etc/luci-sso/secret.key", "01234567890123456789012345678901");

		// 1. Fill the "disk" with 100 handshakes (the hard limit)
		// We mock stat to provide incremental mtimes for sorting
		let mtime = 1000;
		io.stat = (path) => ({ mtime: mtime++ });

		for (let i = 0; i < 100; i++) {
			let res = session.create_state(make_session_deps(io));
			assert.match(truthy(), res.ok, `Failed to create handshake #${i}: ${res.error}`);
		}

		let files = io.lsdir("/var/run/luci-sso");
		let files_before = 0;
		for (let f in files) if (match(f, /^handshake_.*\.json$/)) files_before++;
		
		assert.match(100, files_before, "Should have exactly 100 handshake files");

		// 2. The 101st handshake should trigger an emergency reap of the oldest 50%
		let res_101 = session.create_state(make_session_deps(io));
		assert.match(truthy(), res_101.ok, "101st handshake should succeed after emergency reap");

		files = io.lsdir("/var/run/luci-sso");
		let files_after = 0;
		for (let f in files) if (match(f, /^handshake_.*\.json$/)) files_after++;
		
		// Expected: 100 (original) - 50 (reaped) + 1 (new) = 51
		assert.match(51, files_after, "Emergency reap should have cleared 50% of oldest handshakes");
	});
});
