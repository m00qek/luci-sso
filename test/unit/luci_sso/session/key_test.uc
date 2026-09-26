import { describe, it, assert, contains, has_length, truthy, mock, spy } from 'utest';
import * as key from 'luci_sso.session.key';
import * as common from 'luci_sso.session.common';
import * as native from 'luci_sso.native';

const NOW    = 1700000000;
const SECRET = 'aaaabbbbccccddddeeeeffffgggghhhh';
const LOCK   = common.SECRET_KEY_PATH + '.lock';

function make_deps(injected) {
	return { fs: injected.fs, clock: injected.clock, native: injected.native ?? native, log: () => null };
}

// The lock is a directory. The utest fs mock does not model directories (mkdir
// always succeeds, unlink removes anything, rmdir is sealed), so tests that touch
// the lock use this stand-in with real semantics: mkdir fails while the lock is
// held, rmdir releases it, and unlink refuses it with EISDIR as the real fs does.
function lock_dir(held) {
	let state = { held };
	state.behavior = {
		mkdir: (path) => {
			if (path !== LOCK) return true;
			if (state.held) return false;
			state.held = true;
			return true;
		},
		rmdir: (path) => {
			if (path !== LOCK || !state.held) return false;
			state.held = false;
			return true;
		},
		unlink: (path) => path !== LOCK
	};
	return state;
}

// Default spec for the generation path: an absent key, a free lock.
function gen_fs(extra) {
	let lock = lock_dir(false);
	return { lock, spec: { strict: true, data: { [common.SECRET_KEY_PATH]: '' }, behavior: { ...lock.behavior, ...(extra || {}) } } };
}

// ─── key exists on disk ───────────────────────────────────────────────────────

describe('session.key: get — key exists on disk', () => {
	it('returns the key when the file is non-empty', () => {
		let data = {};
		data[common.SECRET_KEY_PATH] = SECRET;
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: true, data: SECRET }), key.get(make_deps(injected)));
		});
	});
});

// ─── lock acquired — generation path ─────────────────────────────────────────

describe('session.key: get — lock acquired', () => {
	it('generates and returns a 32-byte key when the file is absent', () => {
		let g = gen_fs();
		mock.inject_all({ fs: g.spec, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			let res = key.get(make_deps(injected));
			assert.match(contains({ ok: true, data: has_length(32) }), res);
		});
	});

	it('releases the lock directory with rmdir, never unlink', () => {
		let g = gen_fs();
		mock.inject_all({ fs: g.spec, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			key.get(make_deps(injected));
			assert.match(false, g.lock.held, 'lock must be released after generation');
			assert.match(contains([[LOCK]]), spy(injected.fs).calls.rmdir);
			for (let c in (spy(injected.fs).calls.unlink || []))
				assert.match(truthy(), c[0] !== LOCK, 'unlink must never target the lock directory');
		});
	});

	it('persists the generated key to SECRET_KEY_PATH', () => {
		let g = gen_fs();
		mock.inject_all({ fs: g.spec, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			key.get(make_deps(injected));
			let stored = injected.fs.readfile(common.SECRET_KEY_PATH);
			assert.match(32, length(stored));
		});
	});

	it('returns CRYPTO_INIT_FAILED when CSPRNG fails', () => {
		let g = gen_fs();
		mock.inject_all({
			fs:     g.spec,
			clock:  { strict: true, data: { now: NOW } },
			native: { behavior: { random: () => null } },
		}, (injected) => {
			assert.match(contains({ ok: false, error: 'CRYPTO_INIT_FAILED' }), key.get(make_deps(injected)));
			assert.match(false, g.lock.held, 'lock must be released on CSPRNG failure');
		});
	});

	it('returns SYSTEM_KEY_WRITE_FAILED when writefile fails', () => {
		let g = gen_fs({ writefile: () => false });
		mock.inject_all({
			fs:    g.spec,
			clock: { strict: true, data: { now: NOW } },
		}, (injected) => {
			assert.match(contains({ ok: false, error: 'SYSTEM_KEY_WRITE_FAILED' }), key.get(make_deps(injected)));
			assert.match(false, g.lock.held, 'lock must be released on write failure');
		});
	});

	it('returns SYSTEM_KEY_WRITE_FAILED when rename fails', () => {
		let g = gen_fs({ rename: () => false });
		mock.inject_all({
			fs:    g.spec,
			clock: { strict: true, data: { now: NOW } },
		}, (injected) => {
			assert.match(contains({ ok: false, error: 'SYSTEM_KEY_WRITE_FAILED' }), key.get(make_deps(injected)));
			assert.match(false, g.lock.held, 'lock must be released on rename failure');
		});
	});

	it('never returns ok(null) when a syscall dies mid-generation', () => {
		// A die() inside chmod must be caught and surfaced as an error Result — never
		// swallowed into Result.ok(null), which would hand callers a null secret key.
		let g = gen_fs({ chmod: () => die('Permission denied (mocked)') });
		mock.inject_all({
			fs:    g.spec,
			clock: { strict: true, data: { now: NOW } },
		}, (injected) => {
			let res = key.get(make_deps(injected));
			assert.match(contains({ ok: false }), res);
			assert.match(truthy(),
				res.error === 'SYSTEM_KEY_GENERATION_FAILED' || res.error === 'SYSTEM_KEY_WRITE_FAILED',
				`Expected a generation/write failure, got: ${res.error}`);
		});
	});
});

// ─── lock contention ─────────────────────────────────────────────────────────

describe('session.key: get — lock contention', () => {
	it('self-heals a stale lock (age > 30s) and generates a new key', () => {
		// The lock directory is held and 31s old: it must be removed with rmdir and
		// re-acquired. Removing it with unlink fails on a directory, which left the
		// lock in place forever and sent every caller into the retry loop.
		let lock = lock_dir(true);
		mock.inject_all({
			fs:    { strict: true, data: { [common.SECRET_KEY_PATH]: '' },
			         behavior: { ...lock.behavior, stat: () => ({ mtime: NOW - 31, size: 0, type: 'directory' }) } },
			clock: { strict: true, data: { now: NOW } },
		}, (injected) => {
			assert.match(contains({ ok: true, data: has_length(32) }), key.get(make_deps(injected)));
			assert.match(false, lock.held, 'lock must be released after self-heal and generation');
		});
	});

	it('returns the key when it appears in the file during retry backoff', () => {
		// Lock is held by another process; the key file is written by that process
		// after the second sleep (read_calls reaches 3 on the second retry iteration).
		let read_calls = 0;
		mock.inject_all({
			fs: {
				strict: true,
				data: {},
				behavior: {
					mkdir:    () => false,
					stat:     () => ({ mtime: NOW - 1, size: 0 }),
					readfile: (path) => {
						if (path !== common.SECRET_KEY_PATH) return null;
						read_calls++;
						return read_calls >= 3 ? SECRET : null;
					}
				}
			},
			clock: { strict: true, data: { now: NOW } }
		}, (injected) => {
			assert.match(contains({ ok: true, data: SECRET }), key.get(make_deps(injected)));
		});
	});

	it('returns SYSTEM_KEY_UNAVAILABLE after all retries are exhausted', () => {
		mock.inject_all({
			fs: {
				strict: true,
				data: { [common.SECRET_KEY_PATH]: '' },
				behavior: { mkdir: () => false, stat: () => null }
			},
			clock: { strict: true, data: { now: NOW } }
		}, (injected) => {
			assert.match(contains({ ok: false, error: 'SYSTEM_KEY_UNAVAILABLE' }), key.get(make_deps(injected)));
		});
	});
});
