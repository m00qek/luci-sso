import { describe, it, assert, contains, has_length, mock } from 'utest';
import * as key from 'luci_sso.session.key';
import * as common from 'luci_sso.session.common';
import * as native from 'luci_sso.native';

const NOW    = 1700000000;
const SECRET = 'aaaabbbbccccddddeeeeffffgggghhhh';
const LOCK   = common.SECRET_KEY_PATH + '.lock';

function make_deps(injected) {
	return { fs: injected.fs, clock: injected.clock, native: injected.native ?? native, log: () => null };
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
		mock.inject_all({ fs: { strict: true, data: {} }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			let res = key.get(make_deps(injected));
			assert.match(contains({ ok: true, data: has_length(32) }), res);
		});
	});

	it('persists the generated key to SECRET_KEY_PATH', () => {
		mock.inject_all({ fs: { strict: true, data: {} }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			key.get(make_deps(injected));
			let stored = injected.fs.readfile(common.SECRET_KEY_PATH);
			assert.match(32, length(stored));
		});
	});

	it('returns CRYPTO_INIT_FAILED when CSPRNG fails', () => {
		mock.inject_all({
			fs:     { strict: true, data: {} },
			clock:  { strict: true, data: { now: NOW } },
			native: { behavior: { random: () => null } },
		}, (injected) => {
			assert.match(contains({ ok: false, error: 'CRYPTO_INIT_FAILED' }), key.get(make_deps(injected)));
		});
	});

	it('returns SYSTEM_KEY_WRITE_FAILED when writefile fails', () => {
		mock.inject_all({
			fs:    { strict: true, data: {}, behavior: { writefile: () => false } },
			clock: { strict: true, data: { now: NOW } },
		}, (injected) => {
			assert.match(contains({ ok: false, error: 'SYSTEM_KEY_WRITE_FAILED' }), key.get(make_deps(injected)));
		});
	});

	it('returns SYSTEM_KEY_WRITE_FAILED when rename fails', () => {
		mock.inject_all({
			fs:    { strict: true, data: {}, behavior: { rename: () => false } },
			clock: { strict: true, data: { now: NOW } },
		}, (injected) => {
			assert.match(contains({ ok: false, error: 'SYSTEM_KEY_WRITE_FAILED' }), key.get(make_deps(injected)));
		});
	});
});

// ─── lock contention ─────────────────────────────────────────────────────────

describe('session.key: get — lock contention', () => {
	it('self-heals a stale lock (age > 30s) and generates a new key', () => {
		// Lock directory exists but mtime is 31s ago — triggers self-healing unlink + re-acquire.
		let data = {};
		data[LOCK] = '';
		mock.inject_all({
			fs:    { strict: true, data, behavior: { stat: () => ({ mtime: NOW - 31, size: 0 }) } },
			clock: { strict: true, data: { now: NOW } },
		}, (injected) => {
			assert.match(contains({ ok: true, data: has_length(32) }), key.get(make_deps(injected)));
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
