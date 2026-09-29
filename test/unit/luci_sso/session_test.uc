import { describe, it, assert, contains, regex, not, equals, mock } from 'utest';
import * as session from 'luci_sso.session';
import * as common from 'luci_sso.session.common';
import * as native from 'luci_sso.native';

// session.uc is a pure façade over session.handshake. These tests assert the
// delegation wiring: each public export routes to the correct submodule
// function. The submodule's own contract is covered in
// session/handshake_test.uc; here each assertion is just distinctive enough to
// prove the right function is behind each name (e.g. a mis-alias of
// create_state → consume would change the shape and fail).

const NOW    = 1700000000;
const B64URL = /^[A-Za-z0-9_-]+$/;

function make_deps(injected) {
	return { fs: injected.fs, clock: injected.clock, native: injected.native ?? native, log: () => null };
}

// empty fs for the handshake create / reap paths.
const EMPTY_FS = {
	// handshake.create/reap list HANDSHAKE_DIR; utest >= 1.5.0 dies in strict
	// mode on an lsdir() of a directory the mock has never seen. The tombstoned
	// child declares it as known-but-empty.
	fs:    { strict: true, data: { [common.HANDSHAKE_DIR + '/.utest-keep']: null } },
	clock: { strict: true, data: { now: NOW } },
};

describe('session: façade delegation', () => {
	it('create_state → handshake.create (returns token/state/nonce/code_challenge)', () => {
		mock.inject_all(EMPTY_FS, (injected) => {
			assert.match(
				contains({ ok: true, data: contains({
					token:          regex(B64URL),
					state:          regex(B64URL),
					nonce:          regex(B64URL),
					code_challenge: regex(B64URL),
				}) }),
				session.create_state(make_deps(injected), 0)
			);
		});
	});

	it('verify_state → handshake.verify (round-trips a freshly created handle)', () => {
		mock.inject_all(EMPTY_FS, (injected) => {
			let deps = make_deps(injected);
			let created = session.create_state(deps, 0);
			assert.match(contains({ ok: true }), created);
			assert.match(contains({ ok: true }), session.verify_state(deps, created.data.token, created.data.state, 0));
		});
	});

	it('consume_state → handshake.consume (deletes the stored handshake)', () => {
		mock.inject_all(EMPTY_FS, (injected) => {
			let deps = make_deps(injected);
			let created = session.create_state(deps, 0);
			let path = `${common.HANDSHAKE_DIR}/handshake_${created.data.token}.json`;
			assert.match(not(equals(null)), injected.fs.readfile(path)); // exists before
			session.consume_state(deps, created.data.token);
			assert.match(null, injected.fs.readfile(path));              // gone after
		});
	});

	it('reap_stale_handshakes → handshake.reap (returns a count)', () => {
		mock.inject_all(EMPTY_FS, (injected) => {
			assert.match(contains({ ok: true, data: 0 }), session.reap_stale_handshakes(make_deps(injected), 0));
		});
	});
});
