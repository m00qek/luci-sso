import { describe, it, assert, contains, regex, truthy, spy, mock } from 'utest';
import * as handshake from 'luci_sso.session.handshake';
import * as common from 'luci_sso.session.common';
import * as native from 'luci_sso.native';

const NOW    = 1700000000;
const DIR    = common.HANDSHAKE_DIR;
const HANDLE = 'AAAAAAAAAAAAAAAA';
const PATH   = DIR + '/handshake_' + HANDLE + '.json';

// Minimum valid PKCE code_verifier: exactly 43 chars, base64url alphabet
const VERIFIER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq';

const B64URL = /^[A-Za-z0-9_-]+$/;

function make_deps(injected) {
	return { fs: injected.fs, clock: injected.clock, native: injected.native ?? native, log: () => null };
}

// Builds a minimal valid serialized handshake payload with optional field overrides.
function make_state(overrides) {
	let data = {
		state:         'state_value',
		code_verifier: VERIFIER,
		nonce:         'nonce_value',
		iat:           NOW,
		exp:           NOW + common.HANDSHAKE_DURATION,
	};
	for (let k in (overrides || {}))
		data[k] = overrides[k];
	return sprintf('%J', data);
}

// ─── reap ────────────────────────────────────────────────────────────────────

describe('session.handshake: reap', () => {
	it('dies for non-integer clock_tolerance', () => {
		mock.inject_all({ fs: { strict: true, data: {} }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			let deps = make_deps(injected);
			assert.throws(() => handshake.reap(deps, '0'),  /CONTRACT_VIOLATION/);
			assert.throws(() => handshake.reap(deps, 0.5), /CONTRACT_VIOLATION/);
		});
	});

	it('returns ok(0) when HANDSHAKE_DIR is empty', () => {
		mock.inject_all({ fs: { data: {}, strict: true }, clock: { data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: true, data: 0 }), handshake.reap(make_deps(injected), 0));
		});
	});

	it('returns ok(0) for files that do not match the handshake pattern', () => {
		let data = {};
		data[DIR + '/other_file.txt'] = 'content';
		mock.inject_all({ fs: { data, strict: true }, clock: { data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: true, data: 0 }), handshake.reap(make_deps(injected), 0));
		});
	});

	it('reaps files older than HANDSHAKE_DURATION + clock_tolerance + REAP_GRACE_PERIOD', () => {
		// The proxy returns mtime: 0 for data entries, but reap uses `st && st.mtime && ...`
		// so mtime must be non-zero. We use stat behavior with mtime: 1.
		// threshold = 300 + 0 + 60 = 360; now - 1 = 361 > 360 → reaps
		let data = {};
		data[DIR + '/handshake_BBBB.json'] = 'old';
		mock.inject_all({ fs: { data, strict: true, behavior: { stat: () => ({ mtime: 1, size: 0, type: 'regular' }) } }, clock: { data: { now: 362 } } }, (injected) => {
			assert.match(contains({ ok: true, data: 1 }), handshake.reap(make_deps(injected), 0));
		});
	});

	it('does not reap files exactly at the threshold (uses > not >=)', () => {
		// now - mtime = 361 - 1 = 360; 360 > 360 is false → not reaped
		let data = {};
		data[DIR + '/handshake_BBBB.json'] = 'borderline';
		mock.inject_all({ fs: { data, strict: true, behavior: { stat: () => ({ mtime: 1, size: 0, type: 'regular' }) } }, clock: { data: { now: 361 } } }, (injected) => {
			assert.match(contains({ ok: true, data: 0 }), handshake.reap(make_deps(injected), 0));
		});
	});

	it('applies clock_tolerance to the reap threshold', () => {
		// threshold = 300 + 60 + 60 = 420; now - 1 = 421 > 420 → reaps
		let data = {};
		data[DIR + '/handshake_BBBB.json'] = 'content';
		mock.inject_all({ fs: { data, strict: true, behavior: { stat: () => ({ mtime: 1, size: 0, type: 'regular' }) } }, clock: { data: { now: 422 } } }, (injected) => {
			assert.match(contains({ ok: true, data: 1 }), handshake.reap(make_deps(injected), 60));
		});
	});

	it('returns the count of reaped files', () => {
		let data = {};
		data[DIR + '/handshake_AA.json'] = 'old';
		data[DIR + '/handshake_BB.json'] = 'old';
		data[DIR + '/handshake_CC.json'] = 'old';
		mock.inject_all({ fs: { data, strict: true, behavior: { stat: () => ({ mtime: 1, size: 0, type: 'regular' }) } }, clock: { data: { now: 362 } } }, (injected) => {
			assert.match(contains({ ok: true, data: 3 }), handshake.reap(make_deps(injected), 0));
		});
	});
});

// ─── create ──────────────────────────────────────────────────────────────────

describe('session.handshake: create', () => {
	it('returns ok with token, state, nonce, code_challenge', () => {
		mock.inject_all({ fs: { data: {}, strict: true }, clock: { data: { now: NOW } } }, (injected) => {
			let res = handshake.create(make_deps(injected));
			assert.match(contains({ ok: true, data: contains({ token: regex(B64URL), state: regex(B64URL), nonce: regex(B64URL), code_challenge: regex(B64URL) }) }), res);
		});
	});

	it('stored JSON has iat == NOW and exp == NOW + HANDSHAKE_DURATION', () => {
		mock.inject_all({ fs: { data: {}, strict: true }, clock: { data: { now: NOW } } }, (injected) => {
			let deps = make_deps(injected);
			let res = handshake.create(deps);
			assert.match(contains({ ok: true }), res);
			let stored = json(injected.fs.readfile(DIR + '/handshake_' + res.data.token + '.json'));
			assert.match(NOW,                            stored.iat);
			assert.match(NOW + common.HANDSHAKE_DURATION, stored.exp);
		});
	});

	it('stored JSON has state, nonce, code_verifier matching the returned values', () => {
		mock.inject_all({ fs: { data: {}, strict: true }, clock: { data: { now: NOW } } }, (injected) => {
			let deps = make_deps(injected);
			let res = handshake.create(deps);
			assert.match(contains({ ok: true }), res);
			let stored = json(injected.fs.readfile(DIR + '/handshake_' + res.data.token + '.json'));
			assert.match(res.data.state, stored.state);
			assert.match(res.data.nonce, stored.nonce);
			assert.match(regex(B64URL),  stored.code_verifier);
		});
	});

	it('triggers emergency reap and still succeeds at HANDSHAKE_MAX_COUNT', () => {
		// At exactly max count, emergency reap removes 50%, leaving 50 — create proceeds
		let data = {};
		for (let i = 0; i < common.HANDSHAKE_MAX_COUNT; i++)
			data[DIR + '/handshake_' + sprintf('%04d', i) + '.json'] = '{}';
		mock.inject_all({ fs: { data, strict: true }, clock: { data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: true }), handshake.create(make_deps(injected)));
		});
	});

	it('returns HANDSHAKE_CAPACITY_EXCEEDED when emergency reap cannot free enough slots', () => {
		// At 2× max, emergency reap removes 50% leaving exactly max → still full
		let data = {};
		for (let i = 0; i < 2 * common.HANDSHAKE_MAX_COUNT; i++)
			data[DIR + '/handshake_' + sprintf('%04d', i) + '.json'] = '{}';
		mock.inject_all({ fs: { data, strict: true }, clock: { data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'HANDSHAKE_CAPACITY_EXCEEDED' }), handshake.create(make_deps(injected)));
		});
	});

	it('writes atomically: tmp file, chmod 0600, then rename to the final path', () => {
		mock.inject_all({ fs: { data: {}, strict: true }, clock: { data: { now: NOW } } }, (injected) => {
			let res = handshake.create(make_deps(injected));
			assert.match(contains({ ok: true }), res);

			let write_op  = (spy(injected.fs).calls.writefile || [])[0];
			let chmod_op  = (spy(injected.fs).calls.chmod     || [])[0];
			let rename_op = (spy(injected.fs).calls.rename    || [])[0];

			assert.match(truthy(), write_op, 'Should have performed a writefile');
			assert.match(truthy(), index(write_op[0], '.tmp') > 0, `Should write to a tmp file first. Got: ${write_op[0]}`);
			assert.match(write_op[0], chmod_op[0], 'chmod should target the tmp file');
			assert.match(0600,        chmod_op[1], 'chmod should set 0600');
			assert.match(write_op[0], rename_op[0], 'rename should move from the tmp file');
			assert.match(-1,          index(rename_op[1], '.tmp'), `rename target must not be temporary. Got: ${rename_op[1]}`);
		});
	});

	it('returns CRYPTO_INIT_FAILED when the CSPRNG fails (Audit B2)', () => {
		mock.inject_all({
			fs:     { data: {}, strict: true },
			clock:  { data: { now: NOW } },
			native: { behavior: { random: () => null } },
		}, (injected) => {
			assert.match(contains({ ok: false, error: 'CRYPTO_INIT_FAILED' }), handshake.create(make_deps(injected)));
		});
	});
});

// ─── consume ─────────────────────────────────────────────────────────────────

describe('session.handshake: consume', () => {
	it('is a no-op for null', () => {
		mock.inject_all({ fs: { strict: true } }, (injected) => {
			handshake.consume({ fs: injected.fs }, null);
		});
	});

	it('is a no-op for a non-string handle', () => {
		mock.inject_all({ fs: { strict: true } }, (injected) => {
			handshake.consume({ fs: injected.fs }, 42);
		});
	});

	it('is a no-op for a handle with non-base64url characters', () => {
		mock.inject_all({ fs: { strict: true } }, (injected) => {
			handshake.consume({ fs: injected.fs }, 'bad handle!');
		});
	});

	it('does not throw for a valid handle whose file does not exist', () => {
		mock.inject_all({ fs: { strict: true, data: {} } }, (injected) => {
			handshake.consume({ fs: injected.fs }, HANDLE);
		});
	});

	it('removes the file for a valid handle (verified by subsequent verify)', () => {
		let data = {};
		data[PATH] = make_state({});
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			let deps = make_deps(injected);
			handshake.consume(deps, HANDLE);
			assert.match(contains({ ok: false, error: 'STATE_NOT_FOUND' }), handshake.verify(deps, HANDLE, 0));
		});
	});
});

// ─── verify ──────────────────────────────────────────────────────────────────

describe('session.handshake: verify', () => {
	it('dies for a non-string handle', () => {
		mock.inject_all({ fs: { strict: true, data: {} }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			let deps = make_deps(injected);
			assert.throws(() => handshake.verify(deps, null, 0), /CONTRACT_VIOLATION/);
			assert.throws(() => handshake.verify(deps, 42,   0), /CONTRACT_VIOLATION/);
		});
	});

	it('dies for a non-integer clock_tolerance', () => {
		mock.inject_all({ fs: { strict: true, data: {} }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			let deps = make_deps(injected);
			assert.throws(() => handshake.verify(deps, HANDLE, '0'),  /CONTRACT_VIOLATION/);
			assert.throws(() => handshake.verify(deps, HANDLE, 0.5), /CONTRACT_VIOLATION/);
		});
	});

	it('returns MALFORMED_STATE_COOKIE for an empty string handle', () => {
		mock.inject_all({ fs: { strict: true, data: {} }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			// regex uses + (one-or-more), so empty string does not match
			assert.match(contains({ ok: false, error: 'MALFORMED_STATE_COOKIE' }), handshake.verify(make_deps(injected), '', 0));
		});
	});

	it('returns MALFORMED_STATE_COOKIE for handle with non-base64url characters', () => {
		mock.inject_all({ fs: { strict: true, data: {} }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			let deps = make_deps(injected);
			assert.match(contains({ ok: false, error: 'MALFORMED_STATE_COOKIE' }), handshake.verify(deps, 'bad handle!', 0));
			assert.match(contains({ ok: false, error: 'MALFORMED_STATE_COOKIE' }), handshake.verify(deps, '../etc/passwd', 0));
		});
	});

	it('returns STATE_NOT_FOUND when the file does not exist', () => {
		mock.inject_all({ fs: { strict: true, data: {} }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'STATE_NOT_FOUND' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('returns STATE_CORRUPTED for invalid JSON content', () => {
		let data = {};
		data[PATH] = 'not json at all';
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'STATE_CORRUPTED' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('returns STATE_CORRUPTED when code_verifier is missing', () => {
		let data = {};
		data[PATH] = make_state({ code_verifier: null });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'STATE_CORRUPTED' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('returns STATE_CORRUPTED when code_verifier is shorter than 43 chars', () => {
		let data = {};
		data[PATH] = make_state({ code_verifier: 'tooshort' });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'STATE_CORRUPTED' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('returns STATE_CORRUPTED when code_verifier exceeds 128 chars', () => {
		let long_verifier = '';
		for (let i = 0; i < 129; i++) long_verifier += 'A';
		let data = {};
		data[PATH] = make_state({ code_verifier: long_verifier });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'STATE_CORRUPTED' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('returns STATE_CORRUPTED when state is missing', () => {
		let data = {};
		data[PATH] = make_state({ state: null });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'STATE_CORRUPTED' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('returns STATE_CORRUPTED when nonce is missing', () => {
		let data = {};
		data[PATH] = make_state({ nonce: null });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'STATE_CORRUPTED' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('returns STATE_CORRUPTED when exp is missing', () => {
		let data = {};
		data[PATH] = make_state({ exp: null });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'STATE_CORRUPTED' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('returns STATE_CORRUPTED when iat is missing', () => {
		let data = {};
		data[PATH] = make_state({ iat: null });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'STATE_CORRUPTED' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('returns HANDSHAKE_EXPIRED when exp < now - clock_tolerance', () => {
		let data = {};
		data[PATH] = make_state({ exp: NOW - 100 });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'HANDSHAKE_EXPIRED' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('returns HANDSHAKE_EXPIRED for exp == 0 (zero is a valid int, not corrupted)', () => {
		// exp: 0 passes the `exp === null` corruption guard but fails the time check.
		// Ensures the distinction between CORRUPTED (null/non-int) and EXPIRED (valid int in the past).
		let data = {};
		data[PATH] = make_state({ exp: 0 });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'HANDSHAKE_EXPIRED' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('accepts exp exactly at the clock tolerance boundary (exp == now - tolerance)', () => {
		// uses '<' not '<=': exp < (now - tolerance) → boundary value passes
		let data = {};
		data[PATH] = make_state({ iat: NOW - 60, exp: NOW - 60 });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: true }), handshake.verify(make_deps(injected), HANDLE, 60));
		});
	});

	it('returns HANDSHAKE_NOT_YET_VALID when iat > now + clock_tolerance', () => {
		let data = {};
		data[PATH] = make_state({ iat: NOW + 100, exp: NOW + common.HANDSHAKE_DURATION + 100 });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(contains({ ok: false, error: 'HANDSHAKE_NOT_YET_VALID' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});

	it('returns ok with the full handshake payload for a valid state', () => {
		let data = {};
		data[PATH] = make_state({});
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			assert.match(
				contains({ ok: true, data: contains({ state: 'state_value', nonce: 'nonce_value', code_verifier: VERIFIER }) }),
				handshake.verify(make_deps(injected), HANDLE, 0)
			);
		});
	});

	it('is one-time use: second verify returns STATE_NOT_FOUND', () => {
		let data = {};
		data[PATH] = make_state({});
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			let deps = make_deps(injected);
			assert.match(contains({ ok: true }),                          handshake.verify(deps, HANDLE, 0));
			assert.match(contains({ ok: false, error: 'STATE_NOT_FOUND' }), handshake.verify(deps, HANDLE, 0));
		});
	});

	it('file is consumed even when HANDSHAKE_EXPIRED', () => {
		let data = {};
		data[PATH] = make_state({ exp: NOW - 100 });
		mock.inject_all({ fs: { strict: true, data }, clock: { strict: true, data: { now: NOW } } }, (injected) => {
			let deps = make_deps(injected);
			assert.match(contains({ ok: false, error: 'HANDSHAKE_EXPIRED' }), handshake.verify(deps, HANDLE, 0));
			assert.match(contains({ ok: false, error: 'STATE_NOT_FOUND' }),    handshake.verify(deps, HANDLE, 0));
		});
	});

	it('removes the .consumed file even when the post-rename read fails (Audit W5)', () => {
		// verify renames the state to <path>.consumed, then reads it. If the read
		// fails, the .consumed file must still be unlinked so it cannot linger.
		let data = {};
		data[PATH] = make_state({});
		mock.inject_all({
			fs:    { strict: true, data, behavior: { readfile: () => null } },
			clock: { strict: true, data: { now: NOW } },
		}, (injected) => {
			let res = handshake.verify(make_deps(injected), HANDLE, 0);
			assert.match(contains({ ok: false }), res, 'Should fail due to the read error');

			let removed = false;
			for (let call in (spy(injected.fs).calls.unlink || []))
				if (call[0] === PATH + '.consumed') removed = true;
			assert.match(truthy(), removed, 'Must unlink the .consumed file even when the read fails');
		});
	});

	it('does not recover state from a pre-existing .consumed file when rename fails (strict one-time use)', () => {
		// An attacker-planted <path>.consumed must never be honoured: if the atomic
		// rename that claims the state fails, verify must report STATE_NOT_FOUND.
		let data = {};
		data[PATH + '.consumed'] = make_state({ exp: NOW + 100000 });
		mock.inject_all({
			fs:    { strict: true, data, behavior: { rename: () => false } },
			clock: { strict: true, data: { now: NOW } },
		}, (injected) => {
			assert.match(contains({ ok: false, error: 'STATE_NOT_FOUND' }), handshake.verify(make_deps(injected), HANDLE, 0));
		});
	});
});
