import { describe, it, assert, contains, regex, not, equals, mock } from 'utest';
import * as session from 'luci_sso.session';
import * as common from 'luci_sso.session.common';
import * as native from 'luci_sso.native';

// session.uc is a pure façade over session.key / session.handshake / session.token.
// These tests assert the delegation wiring: each public export routes to the
// correct submodule function. The submodules' own contracts are covered in
// session/{key,handshake,token}_test.uc; here each assertion is just distinctive
// enough to prove the right function is behind each name (e.g. a mis-alias of
// create_state → consume would change the shape and fail).

const SECRET = 'aaaabbbbccccddddeeeeffffgggghhhh';
const NOW    = 1700000000;
const B64URL = /^[A-Za-z0-9_-]+$/;

function make_deps(injected) {
	return { fs: injected.fs, clock: injected.clock, native: injected.native ?? native, log: () => null };
}

// fs pre-seeded with the secret key so key.get / token.* succeed.
const WITH_SECRET = {
	fs:    { strict: true, data: { [common.SECRET_KEY_PATH]: SECRET } },
	clock: { strict: true, data: { now: NOW } },
};

// empty fs for the handshake create / reap paths.
const EMPTY_FS = {
	// handshake.create/reap list HANDSHAKE_DIR; utest >= 1.5.0 dies in strict
	// mode on an lsdir() of a directory the mock has never seen. The tombstoned
	// child declares it as known-but-empty.
	fs:    { strict: true, data: { [common.HANDSHAKE_DIR + '/.utest-keep']: null } },
	clock: { strict: true, data: { now: NOW } },
};

describe('session: façade delegation', () => {
	it('get_secret_key → key.get (returns the on-disk secret)', () => {
		mock.inject_all(WITH_SECRET, (injected) => {
			assert.match(contains({ ok: true, data: SECRET }), session.get_secret_key(make_deps(injected)));
		});
	});

	it('create_state → handshake.create (returns token/state/nonce/code_challenge)', () => {
		mock.inject_all(EMPTY_FS, (injected) => {
			assert.match(
				contains({ ok: true, data: contains({
					token:          regex(B64URL),
					state:          regex(B64URL),
					nonce:          regex(B64URL),
					code_challenge: regex(B64URL),
				}) }),
				session.create_state(make_deps(injected))
			);
		});
	});

	it('verify_state → handshake.verify (round-trips a freshly created handle)', () => {
		mock.inject_all(EMPTY_FS, (injected) => {
			let deps = make_deps(injected);
			let created = session.create_state(deps);
			assert.match(contains({ ok: true }), created);
			assert.match(contains({ ok: true }), session.verify_state(deps, created.data.token, 0));
		});
	});

	it('consume_state → handshake.consume (deletes the stored handshake)', () => {
		mock.inject_all(EMPTY_FS, (injected) => {
			let deps = make_deps(injected);
			let created = session.create_state(deps);
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

	it('create → token.create (returns a three-part JWS)', () => {
		mock.inject_all(WITH_SECRET, (injected) => {
			let res = session.create(make_deps(injected), { sub: 'uid-123' });
			assert.match(contains({ ok: true }), res);
			assert.match(3, length(split(res.data, '.')));
		});
	});

	it('verify → token.verify (round-trips a freshly created token)', () => {
		mock.inject_all(WITH_SECRET, (injected) => {
			let deps = make_deps(injected);
			let tok = session.create(deps, { sub: 'uid-123' });
			assert.match(contains({ ok: true }), tok);
			assert.match(contains({ ok: true, data: { user: 'uid-123' } }), session.verify(deps, tok.data, 0));
		});
	});
});
