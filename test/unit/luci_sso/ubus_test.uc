import { describe, it, afterEach, assert, contains, mock } from 'utest';
import * as ubus_mod from 'luci_sso.ubus';
import * as Result from 'luci_sso.result';
import * as crypto from 'luci_sso.crypto';
import * as real_native from 'luci_sso.native';

const NOW     = 1700000000;
const SID     = 'aabbccdd11223344aabbccdd11223344';
const ACL_DIR = '/usr/share/rpcd/acl.d';
const TOK_DIR = '/var/run/luci-sso/tokens';

const broken_random = {
	random:             () => null,
	sha256:             real_native.sha256,
	hmac_sha256:        real_native.hmac_sha256,
	verify_rs256:       real_native.verify_rs256,
	verify_es256:       real_native.verify_es256,
	jwk_rsa_to_pem:     real_native.jwk_rsa_to_pem,
	jwk_ec_p256_to_pem: real_native.jwk_ec_p256_to_pem,
};

// Wraps proxies into the deps shape expected by ubus.uc, mirroring context.uc.
// deps.ubus.call() returns Result.ok(raw) or Result.err("UBUS_ERROR") when raw is null.
function build_deps(proxies) {
	let deps = { log: () => null };
	if (proxies.ubus) {
		let conn = proxies.ubus.connect();
		deps.ubus = {
			__utest__: conn ? conn.__utest__ : null,
			call: (obj, method, args) => {
				let raw = conn.call(obj, method, args);
				if (raw === null) return Result.err("UBUS_ERROR");
				return Result.ok(raw);
			},
		};
	}
	if (proxies.fs)    deps.fs    = proxies.fs;
	if (proxies.clock) deps.clock = proxies.clock;
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
		mock.inject_all({ ubus: {} }, (proxies) => {
			assert.match(contains({ ok: false, error: 'INVALID_SID' }),
				ubus_mod.get_session(build_deps(proxies), null));
		});
	});

	it('returns INVALID_SID for a non-string', () => {
		mock.inject_all({ ubus: {} }, (proxies) => {
			assert.match(contains({ ok: false, error: 'INVALID_SID' }),
				ubus_mod.get_session(build_deps(proxies), 42));
		});
	});

	it('returns SESSION_NOT_FOUND when the ubus call fails', () => {
		// No "session:get" data → proxy returns null → Result.err → SESSION_NOT_FOUND
		mock.inject_all({ ubus: {} }, (proxies) => {
			assert.match(contains({ ok: false, error: 'SESSION_NOT_FOUND' }),
				ubus_mod.get_session(build_deps(proxies), SID));
		});
	});

	it('returns SESSION_NOT_FOUND when the response values field is not an object', () => {
		mock.inject_all({ ubus: { data: { "session:get": { values: 'string' } } } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'SESSION_NOT_FOUND' }),
				ubus_mod.get_session(build_deps(proxies), SID));
		});
	});

	it('returns ok(values) on success', () => {
		let vals = { username: 'root', oidc_user: 'alice@example.com' };
		mock.inject_all({ ubus: { data: { "session:get": { values: vals } } } }, (proxies) => {
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
		mock.inject_all({ ubus: {} }, (proxies) => {
			assert.match(contains({ ok: false, error: 'INVALID_SID' }),
				ubus_mod.destroy_session(build_deps(proxies), null));
		});
	});

	it('returns UBUS_ERROR when the destroy call fails', () => {
		// No "session:destroy" data → proxy returns null → Result.err → UBUS_ERROR
		mock.inject_all({ ubus: {} }, (proxies) => {
			assert.match(contains({ ok: false, error: 'UBUS_ERROR' }),
				ubus_mod.destroy_session(build_deps(proxies), SID));
		});
	});

	it('returns ok() on success', () => {
		mock.inject_all({ ubus: { data: { "session:destroy": {} } } }, (proxies) => {
			assert.match(contains({ ok: true }),
				ubus_mod.destroy_session(build_deps(proxies), SID));
		});
	});
});

// ─── reap_stale_tokens ───────────────────────────────────────────────────────

describe('ubus: reap_stale_tokens', () => {
	it('returns ok(0) when the token directory does not exist', () => {
		mock.inject_all({
			fs:    { behavior: { lsdir: () => null } },
			clock: { data: { now: NOW } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: 0 }), ubus_mod.reap_stale_tokens(build_deps(proxies)));
		});
	});

	it('returns ok(0) when the token directory is empty', () => {
		mock.inject_all({
			fs:    { behavior: { lsdir: () => [] } },
			clock: { data: { now: NOW } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: 0 }), ubus_mod.reap_stale_tokens(build_deps(proxies)));
		});
	});

	it('does not reap files younger than 24 hours', () => {
		mock.inject_all({
			fs: {
				behavior: {
					lsdir:  () => ['tok1'],
					stat:   () => ({ mtime: NOW - 86399 }),
					unlink: () => null,
				},
			},
			clock: { data: { now: NOW } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: 0 }), ubus_mod.reap_stale_tokens(build_deps(proxies)));
		});
	});

	it('reaps files older than 24 hours', () => {
		mock.inject_all({
			fs: {
				behavior: {
					lsdir:  () => ['tok1', 'tok2'],
					stat:   () => ({ mtime: NOW - 86401 }),
					unlink: () => null,
				},
			},
			clock: { data: { now: NOW } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: 2 }), ubus_mod.reap_stale_tokens(build_deps(proxies)));
		});
	});

	it('reaps only files past the threshold when ages are mixed', () => {
		mock.inject_all({
			fs: {
				behavior: {
					lsdir:  () => ['old', 'new'],
					stat:   (path) => ({ mtime: path === TOK_DIR + '/old' ? NOW - 86401 : NOW - 100 }),
					unlink: () => null,
				},
			},
			clock: { data: { now: NOW } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: 1 }), ubus_mod.reap_stale_tokens(build_deps(proxies)));
		});
	});
});

// ─── register_token ──────────────────────────────────────────────────────────

describe('ubus: register_token', () => {
	it('returns INVALID_TOKEN for null', () => {
		mock.inject_all({ fs: {} }, (proxies) => {
			assert.match(contains({ ok: false, error: 'INVALID_TOKEN' }),
				ubus_mod.register_token(build_deps(proxies), null));
		});
	});

	it('returns INVALID_TOKEN for a non-string', () => {
		mock.inject_all({ fs: {} }, (proxies) => {
			assert.match(contains({ ok: false, error: 'INVALID_TOKEN' }),
				ubus_mod.register_token(build_deps(proxies), 42));
		});
	});

	it('returns ok() for a new token (lock directory created successfully)', () => {
		// Default fs proxy mkdir returns true
		mock.inject_all({ fs: {} }, (proxies) => {
			assert.match(contains({ ok: true }),
				ubus_mod.register_token(build_deps(proxies), 'access-token'));
		});
	});

	it('returns TOKEN_REPLAYED when the lock directory already exists', () => {
		mock.inject_all({ fs: { behavior: { mkdir: () => false } } }, (proxies) => {
			assert.match(contains({ ok: false, error: 'TOKEN_REPLAYED' }),
				ubus_mod.register_token(build_deps(proxies), 'access-token'));
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
		// No "session:create" data → proxy returns null → Result.err → UBUS_SESSION_FAILED
		mock.inject_all({ ubus: {}, fs: {} }, (proxies) => {
			assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
				));
		});
	});

	it('returns UBUS_SESSION_FAILED when the session response carries no sid', () => {
		mock.inject_all({
			ubus: { data: { "session:create": {} } },
			fs:   {},
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
			ubus: { data: { "session:create": { ubus_rpc_session: SID } } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: SID }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'guest', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
				));
		});
	});
});

describe('ubus: create_passwordless_session — admin wildcard', () => {
	it('detects wildcard in read and grants full access', () => {
		mock.inject_all({
			ubus: { data: { "session:create": { ubus_rpc_session: SID } } },
			fs:   { behavior: { lsdir: () => [] } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: SID }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'root', { read: ['*'], write: [] }, 'a@e.com', 'at', 'rt', 'it'
				));
		});
	});

	it('detects wildcard in write and grants full access', () => {
		mock.inject_all({
			ubus: { data: { "session:create": { ubus_rpc_session: SID } } },
			fs:   { behavior: { lsdir: () => [] } },
		}, (proxies) => {
			assert.match(contains({ ok: true, data: SID }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'root', { read: [], write: ['*'] }, 'a@e.com', 'at', 'rt', 'it'
				));
		});
	});

	it('returns UBUS_SESSION_FAILED and destroys the session when ACL scan fails', () => {
		mock.inject_all({
			ubus: { data: { "session:create": { ubus_rpc_session: SID } } },
			fs:   { behavior: { lsdir: () => null } },
		}, (proxies) => {
			let deps = build_deps(proxies);
			let res = ubus_mod.create_passwordless_session(
				deps, 'root', PERMS_ADMIN, 'a@e.com', 'at', 'rt', 'it'
			);
			assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }), res);
			let destroys = filter(deps.ubus.__utest__.calls.call, (c) => c[1] === 'destroy');
			assert.match(1, length(destroys));
		});
	});
});

describe('ubus: create_passwordless_session — CSPRNG failure', () => {
	afterEach(() => { crypto.set_native(null); });

	it('returns CRYPTO_INIT_FAILED when CSPRNG fails', () => {
		crypto.set_native(broken_random);
		mock.inject_all({
			ubus: { data: { "session:create": { ubus_rpc_session: SID } } },
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
			ubus: { data: { "session:create": { ubus_rpc_session: SID } } },
			fs: {
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
			grants = filter(deps.ubus.__utest__.calls.call,
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
});
