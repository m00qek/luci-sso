import { describe, it, prop, gen, assert, contains, mock } from 'utest';
import * as token from 'luci_sso.session.token';
import * as crypto from 'luci_sso.crypto';
import * as common from 'luci_sso.session.common';

const SECRET = 'aaaabbbbccccddddeeeeffffgggghhhh';
const NOW    = 1700000000;

// key.get succeeds: secret file pre-seeded in the in-memory fs
const KEY_STATE = {
	fs:    { strict: true, data: { '/etc/luci-sso/secret.key': SECRET } },
	clock: { strict: true, data: { now: NOW } },
};

// key.get fails: empty key file + lock held. mkdir is the only op with no data equivalent.
// stat: () => null prevents the strict die on fs.stat(lock_path) which is outside try/catch.
const KEY_FAIL_STATE = {
	fs:    { strict: true, data: { '/etc/luci-sso/secret.key': '' }, behavior: { mkdir: () => false, stat: () => null } },
	clock: { strict: true, data: { now: NOW } },
};

// ─── create ──────────────────────────────────────────────────────────────────

describe('session.token: create', () => {
	it('returns INVALID_USER_DATA for null', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			assert.match(contains({ ok: false, error: 'INVALID_USER_DATA' }), token.create(deps, null));
		});
	});

	it('returns INVALID_USER_DATA when neither sub nor email is a string', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			assert.match(contains({ ok: false, error: 'INVALID_USER_DATA' }), token.create(deps, {}));
			assert.match(contains({ ok: false, error: 'INVALID_USER_DATA' }), token.create(deps, { sub: 42, email: null }));
		});
	});

	it('propagates key.get errors', () => {
		mock.inject_all(KEY_FAIL_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			assert.match(contains({ ok: false, error: 'SYSTEM_KEY_UNAVAILABLE' }), token.create(deps, { sub: 'alice' }));
		});
	});

	it('returns a three-part JWS token', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let res = token.create(deps, { sub: 'alice' });
			assert.match(contains({ ok: true }), res);
			assert.match(3, length(split(res.data, '.')));
		});
	});

	it('uses email as user when present', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let res = token.create(deps, { email: 'alice@example.com', sub: 'uid-123' });
			assert.match(
				contains({ ok: true, data: { user: 'alice@example.com' } }),
				crypto.jws_verify(res.data, SECRET)
			);
		});
	});

	it('falls back to sub when email is absent', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let res = token.create(deps, { sub: 'uid-123' });
			assert.match(
				contains({ ok: true, data: { user: 'uid-123' } }),
				crypto.jws_verify(res.data, SECRET)
			);
		});
	});

	it('sets iat == NOW and exp == NOW + SESSION_DURATION', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let res = token.create(deps, { sub: 'alice' });
			assert.match(
				contains({ ok: true, data: { iat: NOW, exp: NOW + common.SESSION_DURATION } }),
				crypto.jws_verify(res.data, SECRET)
			);
		});
	});

	it('stores name from user_data', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let res = token.create(deps, { sub: 'alice', name: 'Alice Liddell' });
			assert.match(
				contains({ ok: true, data: { name: 'Alice Liddell' } }),
				crypto.jws_verify(res.data, SECRET)
			);
		});
	});

	it('name is null when absent from user_data', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let res = token.create(deps, { sub: 'alice' });
			assert.match(
				contains({ ok: true, data: { name: null } }),
				crypto.jws_verify(res.data, SECRET)
			);
		});
	});
});

// ─── verify ──────────────────────────────────────────────────────────────────

describe('session.token: verify', () => {
	it('returns NO_SESSION for null', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			assert.match(contains({ ok: false, error: 'NO_SESSION' }), token.verify(deps, null, 0));
		});
	});

	it('returns NO_SESSION for empty string', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			assert.match(contains({ ok: false, error: 'NO_SESSION' }), token.verify(deps, '', 0));
		});
	});

	it('dies for a non-string truthy token', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			assert.throws(() => token.verify(deps, 42, 0), /CONTRACT_VIOLATION/);
		});
	});

	it('dies for a non-integer clock_tolerance', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			assert.throws(() => token.verify(deps, 'a.b.c', '0'),  /CONTRACT_VIOLATION/);
			assert.throws(() => token.verify(deps, 'a.b.c', 0.5), /CONTRACT_VIOLATION/);
		});
	});

	it('propagates key.get errors', () => {
		mock.inject_all(KEY_FAIL_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = crypto.jws_sign({ user: 'x', iat: NOW, exp: NOW + 3600 }, SECRET);
			assert.match(contains({ ok: false, error: 'SYSTEM_KEY_UNAVAILABLE' }), token.verify(deps, tok.data, 0));
		});
	});

	it('returns SESSION_SIGNATURE_INVALID for a token signed with a different secret', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = crypto.jws_sign({ user: 'x', iat: NOW, exp: NOW + 3600 }, 'zzzzyyyyyxxxxwwwwvvvvuuuuttttssss');
			assert.match(contains({ ok: false, error: 'SESSION_SIGNATURE_INVALID' }), token.verify(deps, tok.data, 0));
		});
	});

	it('returns SESSION_SIGNATURE_INVALID for a tampered token', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = token.create(deps, { sub: 'alice' });
			assert.match(contains({ ok: false, error: 'SESSION_SIGNATURE_INVALID' }), token.verify(deps, tok.data + 'X', 0));
		});
	});

	it('returns MALFORMED_SESSION_TOKEN when exp is missing', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = crypto.jws_sign({ user: 'x', iat: NOW }, SECRET);
			assert.match(contains({ ok: false, error: 'MALFORMED_SESSION_TOKEN' }), token.verify(deps, tok.data, 0));
		});
	});

	it('returns MALFORMED_SESSION_TOKEN when exp is not an integer', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = crypto.jws_sign({ user: 'x', iat: NOW, exp: '1700003600' }, SECRET);
			assert.match(contains({ ok: false, error: 'MALFORMED_SESSION_TOKEN' }), token.verify(deps, tok.data, 0));
		});
	});

	it('returns SESSION_EXPIRED when exp is in the past', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = crypto.jws_sign({ user: 'x', iat: NOW - 3700, exp: NOW - 100 }, SECRET);
			assert.match(contains({ ok: false, error: 'SESSION_EXPIRED' }), token.verify(deps, tok.data, 0));
		});
	});

	it('returns SESSION_EXPIRED when exp < now - clock_tolerance', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = crypto.jws_sign({ user: 'x', iat: NOW - 3700, exp: NOW - 61 }, SECRET);
			assert.match(contains({ ok: false, error: 'SESSION_EXPIRED' }), token.verify(deps, tok.data, 60));
		});
	});

	it('accepts exp exactly at the clock tolerance boundary (exp == now - tolerance)', () => {
		// verify uses '<' not '<=': exp < (now - tolerance), so the boundary value passes
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = crypto.jws_sign({ user: 'x', iat: NOW - 60, exp: NOW - 60 }, SECRET);
			assert.match(contains({ ok: true }), token.verify(deps, tok.data, 60));
		});
	});

	it('returns MALFORMED_SESSION_TOKEN when iat is missing', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = crypto.jws_sign({ user: 'x', exp: NOW + 3600 }, SECRET);
			assert.match(contains({ ok: false, error: 'MALFORMED_SESSION_TOKEN' }), token.verify(deps, tok.data, 0));
		});
	});

	it('returns MALFORMED_SESSION_TOKEN when iat is not an integer', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = crypto.jws_sign({ user: 'x', iat: '1700000000', exp: NOW + 3600 }, SECRET);
			assert.match(contains({ ok: false, error: 'MALFORMED_SESSION_TOKEN' }), token.verify(deps, tok.data, 0));
		});
	});

	it('returns SESSION_NOT_YET_VALID when iat is beyond clock tolerance', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = crypto.jws_sign({ user: 'x', iat: NOW + 100, exp: NOW + 3700 }, SECRET);
			assert.match(contains({ ok: false, error: 'SESSION_NOT_YET_VALID' }), token.verify(deps, tok.data, 0));
		});
	});

	it('accepts iat within clock tolerance', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let tok = crypto.jws_sign({ user: 'x', iat: NOW + 30, exp: NOW + 3630 }, SECRET);
			assert.match(contains({ ok: true }), token.verify(deps, tok.data, 60));
		});
	});

	it('create / verify round-trip returns the full session payload', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let created = token.create(deps, { sub: 'alice', name: 'Alice' });
			assert.match(contains({ ok: true }), created);
			assert.match(
				contains({ ok: true, data: { user: 'alice', name: 'Alice', iat: NOW, exp: NOW + common.SESSION_DURATION } }),
				token.verify(deps, created.data, 0)
			);
		});
	});

	it('round-trip preserves email as user', () => {
		mock.inject_all(KEY_STATE, (injected) => {
			let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
			let created = token.create(deps, { email: 'alice@example.com', sub: 'uid-123' });
			assert.match(
				contains({ ok: true, data: { user: 'alice@example.com' } }),
				token.verify(deps, created.data, 0)
			);
		});
	});
});

// ─── roundtrip PBT ───────────────────────────────────────────────────────────

describe('session.token: create → verify roundtrip', () => {
	prop('holds for any string sub, including special characters',
		gen.string({ min_len: 1, max_len: 50 }),
		(sub) => {
			mock.inject_all(KEY_STATE, (injected) => {
				let deps = { fs: injected.fs, clock: injected.clock, log: () => null };
				let created = token.create(deps, { sub });
				assert.match(contains({ ok: true }), created);
				assert.match(
					contains({ ok: true, data: { user: sub } }),
					token.verify(deps, created.data, 0)
				);
			});
		}
	);
});
