import { describe, it, assert, contains, mock, spy } from 'utest';
import * as ubus_mod from 'luci_sso.ubus';
import * as Result from 'luci_sso.result';
import * as native from 'luci_sso.native';

const NOW     = 1700000000;
const SID     = 'aabbccdd11223344aabbccdd11223344';
const ACL_DIR = '/usr/share/rpcd/acl.d';
const TOK_DIR = '/var/run/luci-sso/tokens';

// Wraps proxies into the deps shape expected by ubus.uc, mirroring context.uc.
// deps.ubus.call() returns Result.ok(raw) or Result.err("UBUS_ERROR") when raw is null.
function build_deps(proxies) {
	let deps = { log: () => null };
	if (proxies.ubus) {
		let conn = proxies.ubus.connect();
		deps._ubus_conn = conn;
		deps.ubus = {
			call: (obj, method, args) => {
				let raw = conn.call(obj, method, args);
				if (raw === null) return Result.err("UBUS_ERROR");
				return Result.ok(raw);
			},
		};
	}
	if (proxies.fs)     deps.fs     = proxies.fs;
	if (proxies.clock)  deps.clock  = proxies.clock;
	deps.native = proxies.native ?? native;
	return deps;
}

// ─── get_session ─────────────────────────────────────────────────────────────

describe('ubus: get_session', () => {
	it('returns UBUS_UNAVAILABLE when deps.ubus is null', () => {
		assert.match(contains({ ok: false, error: 'UBUS_UNAVAILABLE' }),
			ubus_mod.get_session({ ubus: null, log: () => null }, SID));
	});

	it('returns UBUS_UNAVAILABLE when deps.ubus has no call function', () => {
		assert.match(contains({ ok: false, error: 'UBUS_UNAVAILABLE' }),
			ubus_mod.get_session({ ubus: {}, log: () => null }, SID));
	});

	it('returns INVALID_SID for null', () => {
		mock.inject_all({ ubus: { strict: true } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'INVALID_SID' }),
				ubus_mod.get_session(build_deps(proxies), null));
		});
	});

	it('returns INVALID_SID for a non-string', () => {
		mock.inject_all({ ubus: { strict: true } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'INVALID_SID' }),
				ubus_mod.get_session(build_deps(proxies), 42));
		});
	});

	it('returns SESSION_NOT_FOUND when the ubus call fails', () => {
		mock.inject_all({ ubus: { strict: true, data: { "session:get": () => null } } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'SESSION_NOT_FOUND' }),
				ubus_mod.get_session(build_deps(proxies), SID));
		});
	});

	it('returns SESSION_NOT_FOUND when the response values field is not an object', () => {
		mock.inject_all({ ubus: { strict: true, data: { "session:get": { values: 'string' } } } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'SESSION_NOT_FOUND' }),
				ubus_mod.get_session(build_deps(proxies), SID));
		});
	});

	it('returns ok(values) on success', () => {
		let vals = { username: 'root', oidc_user: 'alice@example.com' };
		mock.inject_all({ ubus: { strict: true, data: { "session:get": { values: vals } } } }, (proxies) => {
			assert.match(
				contains({ ok: true, data: { username: 'root', oidc_user: 'alice@example.com' } }),
				ubus_mod.get_session(build_deps(proxies), SID));
		});
	});
});

// ─── destroy_session ─────────────────────────────────────────────────────────

describe('ubus: destroy_session', () => {
	it('returns UBUS_UNAVAILABLE when deps.ubus is null', () => {
		assert.match(contains({ ok: false, error: 'UBUS_UNAVAILABLE' }),
			ubus_mod.destroy_session({ ubus: null, log: () => null }, SID));
	});

	it('returns INVALID_SID for null', () => {
		mock.inject_all({ ubus: { strict: true } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'INVALID_SID' }),
				ubus_mod.destroy_session(build_deps(proxies), null));
		});
	});

	it('returns UBUS_ERROR when the destroy call fails', () => {
		mock.inject_all({ ubus: { strict: true, data: { "session:destroy": () => null } } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'UBUS_ERROR' }),
				ubus_mod.destroy_session(build_deps(proxies), SID));
		});
	});

	it('returns ok() on success', () => {
		mock.inject_all({ ubus: { strict: true, data: { "session:destroy": {} } } }, (proxies) => {
			assert.match(contains({ ok: true }),
				ubus_mod.destroy_session(build_deps(proxies), SID));
		});
	});
});

// ─── reap_stale_tokens ───────────────────────────────────────────────────────

describe('ubus: reap_stale_tokens', () => {
	it('returns ok(0) when the token directory does not exist', () => {
		mock.inject_all({
			fs:    { strict: true, behavior: { lsdir: () => null } },
			clock: { strict: true, data: { now: NOW } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: 0 }), ubus_mod.reap_stale_tokens(build_deps(proxies)));
		});
	});

	it('returns ok(0) when the token directory is empty', () => {
		mock.inject_all({
			fs:    { strict: true, behavior: { lsdir: () => [] } },
			clock: { strict: true, data: { now: NOW } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: 0 }), ubus_mod.reap_stale_tokens(build_deps(proxies)));
		});
	});

	it('does not reap files younger than 24 hours', () => {
		mock.inject_all({
			fs: {
				strict: true,
				behavior: {
					lsdir:  () => ['tok1'],
					stat:   () => ({ mtime: NOW - 86399 }),
					unlink: () => null,
				},
			},
			clock: { strict: true, data: { now: NOW } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: 0 }), ubus_mod.reap_stale_tokens(build_deps(proxies)));
		});
	});

	it('reaps files older than 24 hours', () => {
		mock.inject_all({
			fs: {
				strict: true,
				behavior: {
					lsdir:  () => ['tok1', 'tok2'],
					stat:   () => ({ mtime: NOW - 86401 }),
					unlink: () => null,
				},
			},
			clock: { strict: true, data: { now: NOW } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: 2 }), ubus_mod.reap_stale_tokens(build_deps(proxies)));
		});
	});

	it('reaps only files past the threshold when ages are mixed', () => {
		mock.inject_all({
			fs: {
				strict: true,
				behavior: {
					lsdir:  () => ['old', 'new'],
					stat:   (path) => ({ mtime: path === TOK_DIR + '/old' ? NOW - 86401 : NOW - 100 }),
					unlink: () => null,
				},
			},
			clock: { strict: true, data: { now: NOW } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: 1 }), ubus_mod.reap_stale_tokens(build_deps(proxies)));
		});
	});
});

// ─── register_token ──────────────────────────────────────────────────────────

describe('ubus: register_token', () => {
	it('returns INVALID_TOKEN for null', () => {
		mock.inject_all({ fs: { strict: true } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'INVALID_TOKEN' }),
				ubus_mod.register_token(build_deps(proxies), null));
		});
	});

	it('returns INVALID_TOKEN for a non-string', () => {
		mock.inject_all({ fs: { strict: true } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'INVALID_TOKEN' }),
				ubus_mod.register_token(build_deps(proxies), 42));
		});
	});

	it('returns ok() for a new token (lock directory created successfully)', () => {
		// Default fs proxy mkdir returns true
		mock.inject_all({ fs: { strict: true } }, (proxies) => {
			assert.match(contains({ ok: true }),
				ubus_mod.register_token(build_deps(proxies), 'access-token'));
		});
	});

	it('returns TOKEN_REPLAYED when the lock directory already exists', () => {
		mock.inject_all({ fs: { strict: true, behavior: { mkdir: () => false } } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'TOKEN_REPLAYED' }),
				ubus_mod.register_token(build_deps(proxies), 'access-token'));
		});
	});

	it('locks on the full 64-char SHA-256 token id and rejects a replay of the same token (B2)', () => {
		let created = {};
		mock.inject_all({ fs: { strict: true, behavior: {
			mkdir: (path) => {
				if (index(path, '/tokens/') >= 0) {
					if (created[path]) return false;
					created[path] = true;
				}
				return true;
			}
		} } }, (proxies) => {
			let deps = build_deps(proxies);
			let token = 'my-secret-token-123';

			assert.match(contains({ ok: true }), ubus_mod.register_token(deps, token));
			let lock_paths = keys(created);
			assert.match(1, length(lock_paths));
			assert.match(64, length(replace(lock_paths[0], /^.*\//, '')), 'Token id must be a full 64-char SHA-256 hex digest');

			assert.match(contains({ ok: false, error: 'TOKEN_REPLAYED' }), ubus_mod.register_token(deps, token));
			assert.match(contains({ ok: true }), ubus_mod.register_token(deps, token + 'new'));
			assert.match(2, length(keys(created)));
		});
	});

	it('succeeds when the base tokens dir mkdir returns false but the per-token lock is created', () => {
		mock.inject_all({ fs: { strict: true, behavior: {
			mkdir: (path) => match(path, /tokens$/) ? false : true, // base dir "already exists"; lock dir created
		} } }, (proxies) => {
			assert.match(contains({ ok: true }), ubus_mod.register_token(build_deps(proxies), 'token-123'));
		});
	});
});

// ─── create_passwordless_session ─────────────────────────────────────────────

const PERMS_USER  = { read: ['luci-mod-network'], write: ['luci-app-firewall'] };
const PERMS_ADMIN = { read: ['*'], write: [] };

describe('ubus: create_passwordless_session — guards', () => {
	it('dies with CONTRACT_VIOLATION when deps.ubus is null', () => {
		assert.throws(() => ubus_mod.create_passwordless_session(
			{ ubus: null, fs: null, clock: null, log: () => null },
			'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
		), /CONTRACT_VIOLATION/);
	});

	it('dies with CONTRACT_VIOLATION when deps.ubus has no call function', () => {
		assert.throws(() => ubus_mod.create_passwordless_session(
			{ ubus: {}, fs: null, clock: null, log: () => null },
			'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
		), /CONTRACT_VIOLATION/);
	});

	it('returns UBUS_SESSION_FAILED when session creation fails', () => {
		mock.inject_all({ ubus: { strict: true, data: { "session:create": () => null } }, fs: { strict: true } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
				));
		});
	});

	it('returns UBUS_SESSION_FAILED when the session response carries no sid', () => {
		mock.inject_all({
			ubus:   { strict: true, data: { "session:create": {} } },
			fs:     { strict: true },
		}, (proxies) => {
			assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
				));
		});
	});
});

describe('ubus: create_passwordless_session — non-admin', () => {
	it('returns ok(sid) for a user with specific permissions', () => {
		mock.inject_all({
			ubus:   { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": {}, "session:set": {} } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: SID }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'guest', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
				));
		});
	});

	it('issues a session CSRF token of at least 256 bits (43+ base64url chars) (B3)', () => {
		let token_len = 0;
		mock.inject_all({
			ubus: { strict: true, data: {
				"session:create": { ubus_rpc_session: SID },
				"session:grant":  {},
				"session:set":    (args) => { token_len = length(args.values.token); return {}; },
			} },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: SID }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'guest', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
				));
			assert.match(true, token_len >= 43, 'CSRF token MUST be at least 256 bits (43+ chars)');
		});
	});
});

describe('ubus: create_passwordless_session — admin wildcard', () => {
	it('detects wildcard in read and grants full access', () => {
		mock.inject_all({
			ubus:   { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": {}, "session:set": {} } },
			fs:     { strict: true, behavior: { lsdir: () => [] } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: SID }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'root', { read: ['*'], write: [] }, 'a@e.com', 'at', 'rt', 'it'
				));
		});
	});

	it('detects wildcard in write and grants full access', () => {
		mock.inject_all({
			ubus:   { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": {}, "session:set": {} } },
			fs:     { strict: true, behavior: { lsdir: () => [] } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: SID }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'root', { read: [], write: ['*'] }, 'a@e.com', 'at', 'rt', 'it'
				));
		});
	});

	it('returns UBUS_SESSION_FAILED and destroys the session when ACL scan fails', () => {
		mock.inject_all({
			ubus:   { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": {}, "session:destroy": {} } },
			fs:     { strict: true, behavior: { lsdir: () => null } },
		}, (proxies) => {
			let deps = build_deps(proxies);
			let res = ubus_mod.create_passwordless_session(
				deps, 'root', PERMS_ADMIN, 'a@e.com', 'at', 'rt', 'it'
			);
			assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }), res);
			let destroys = filter(spy(deps._ubus_conn).calls.call, (c) => c[1] === 'destroy');
			assert.match(1, length(destroys));
		});
	});

	it('grants the standard ubus/uci/file/cgi-io scopes for a wildcard admin session', () => {
		mock.inject_all({
			ubus:   { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": {}, "session:set": {} } },
			fs:     { strict: true, behavior: { lsdir: () => [] } },
		}, (proxies) => {
			let deps = build_deps(proxies);
			ubus_mod.create_passwordless_session(deps, 'root', { read: ['*'], write: ['*'] }, 'a@e.com', 'at', 'rt', 'it');
			let scopes = map(filter(spy(deps._ubus_conn).calls.call, (c) => c[1] === 'grant'), (c) => c[2].scope);
			for (let s in ['ubus', 'uci', 'file', 'cgi-io'])
				assert.match(true, index(scopes, s) != -1, `should grant ${s} scope`);
		});
	});
});

describe('ubus: create_passwordless_session — CSPRNG failure', () => {
	it('returns CRYPTO_INIT_FAILED when CSPRNG fails', () => {
		mock.inject_all({
			ubus:   { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": {} } },
			native: { strict: true, behavior: { random: () => null } },
		}, (proxies) => {
			assert.match(contains({ ok: false, error: 'CRYPTO_INIT_FAILED' }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
				));
		});
	});
});

// ─── _grant_all_luci_acls (tested via admin session) ─────────────────────────

describe('ubus: _grant_all_luci_acls', () => {
	// Runs an admin session and returns the access-group grant calls made.
	// conn.__utest__.calls.call entries are [obj, method, args] tuples.
	function acl_grants_for(lsdir_fn, readfile_fn) {
		let grants = null;
		mock.inject_all({
			ubus: { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": {}, "session:set": {} } },
			fs: {
				strict: true,
				behavior: {
					lsdir:    lsdir_fn    || (() => []),
					readfile: readfile_fn || (() => null),
				},
			},
		}, (proxies) => {
			let deps = build_deps(proxies);
			ubus_mod.create_passwordless_session(
				deps, 'root', PERMS_ADMIN, 'a@e.com', 'at', 'rt', 'it'
			);
			grants = filter(spy(deps._ubus_conn).calls.call,
				(c) => c[1] === 'grant' && c[2].scope === 'access-group');
		});
		return grants;
	}

	it('skips non-json files', () => {
		let grants = acl_grants_for((p) => p === ACL_DIR ? ['readme.txt', 'notes.md'] : []);
		assert.match(0, length(grants));
	});

	it('skips ACL keys that do not start with luci-', () => {
		let grants = acl_grants_for(
			(p) => p === ACL_DIR ? ['other.json'] : [],
			() => '{"other-service":{}}'
		);
		assert.match(0, length(grants));
	});

	it('skips luci- keys whose value is not an object', () => {
		let grants = acl_grants_for(
			(p) => p === ACL_DIR ? ['luci-bad.json'] : [],
			() => '{"luci-bad":"not-an-object"}'
		);
		assert.match(0, length(grants));
	});

	it('issues one read grant and one write grant per luci-* group', () => {
		let grants = acl_grants_for(
			(p) => p === ACL_DIR ? ['luci-base.json'] : [],
			() => '{"luci-base":{},"not-luci":{}}'
		);
		assert.match(2, length(grants));
		let reads  = filter(grants, (c) => c[2].objects[0][1] === 'read');
		let writes = filter(grants, (c) => c[2].objects[0][1] === 'write');
		assert.match(1, length(reads));
		assert.match(1, length(writes));
		assert.match('luci-base', reads[0][2].objects[0][0]);
	});

	it('robustly skips malformed JSON, array roots, non-object values, and luci- substrings in values', () => {
		// Grants collected across mixed ACL files: one valid, one invalid JSON,
		// one array root, one non-object value, one non-luci key with "luci-" in its value.
		let grants = acl_grants_for(
			(p) => p === ACL_DIR ? ['valid.json', 'bad.json', 'array.json', 'invalid_val.json', 'nonluci.json'] : [],
			(p) => {
				if (index(p, 'valid.json')       >= 0) return '{"luci-base":{"description":"ok"}}';
				if (index(p, 'bad.json')         >= 0) return '{ invalid json !!! }';
				if (index(p, 'array.json')       >= 0) return '["luci-broken"]';
				if (index(p, 'invalid_val.json') >= 0) return '{"luci-evil":"not-an-object"}';
				if (index(p, 'nonluci.json')     >= 0) return '{"non-luci":{"comment":"luci-fake here"}}';
				return null;
			}
		);
		let granted = map(grants, (c) => c[2].objects[0][0]);
		assert.match(true, index(granted, 'luci-base') != -1, 'grants the valid luci- key');
		assert.match(-1, index(granted, 'luci-broken'), 'no grant from an array root');
		assert.match(-1, index(granted, 'luci-evil'), 'no grant when value is not an object');
		assert.match(-1, index(granted, 'luci-fake'), 'no grant for a luci- substring found only in a value (N2)');
	});
});
