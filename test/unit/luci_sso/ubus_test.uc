import { describe, it, afterEach, assert, contains } from 'utest';
import * as ubus_mod from 'luci_sso.ubus';
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

// Builds a ubus mock that records all calls and returns pre-defined responses.
// The default for any unregistered call is { ok: true, data: {} }.
function make_ubus(responses) {
	let log = [];
	return {
		call: (obj, method, params) => {
			push(log, { obj, method, params });
			let key = `${obj}.${method}`;
			if (responses && key in responses) {
				let r = responses[key];
				return type(r) === 'function' ? r(params) : r;
			}
			return { ok: true, data: {} };
		},
		calls: () => log,
	};
}

function make_log() { return () => null; }

// ─── get_session ─────────────────────────────────────────────────────────────

describe('ubus: get_session', () => {
	it('returns UBUS_UNAVAILABLE when deps.ubus is null', () => {
		assert.match(contains({ ok: false, error: 'UBUS_UNAVAILABLE' }),
			ubus_mod.get_session({ ubus: null, log: make_log() }, SID));
	});

	it('returns UBUS_UNAVAILABLE when deps.ubus has no call function', () => {
		assert.match(contains({ ok: false, error: 'UBUS_UNAVAILABLE' }),
			ubus_mod.get_session({ ubus: {}, log: make_log() }, SID));
	});

	it('returns INVALID_SID for null', () => {
		assert.match(contains({ ok: false, error: 'INVALID_SID' }),
			ubus_mod.get_session({ ubus: make_ubus(), log: make_log() }, null));
	});

	it('returns INVALID_SID for a non-string', () => {
		assert.match(contains({ ok: false, error: 'INVALID_SID' }),
			ubus_mod.get_session({ ubus: make_ubus(), log: make_log() }, 42));
	});

	it('returns SESSION_NOT_FOUND when the ubus call fails', () => {
		let ub = make_ubus({ 'session.get': { ok: false, error: 'unknown' } });
		assert.match(contains({ ok: false, error: 'SESSION_NOT_FOUND' }),
			ubus_mod.get_session({ ubus: ub, log: make_log() }, SID));
	});

	it('returns SESSION_NOT_FOUND when the response values field is not an object', () => {
		let ub = make_ubus({ 'session.get': { ok: true, data: { values: 'string' } } });
		assert.match(contains({ ok: false, error: 'SESSION_NOT_FOUND' }),
			ubus_mod.get_session({ ubus: ub, log: make_log() }, SID));
	});

	it('returns ok(values) on success', () => {
		let vals = { username: 'root', oidc_user: 'alice@example.com' };
		let ub = make_ubus({ 'session.get': { ok: true, data: { values: vals } } });
		assert.match(contains({ ok: true, data: { username: 'root', oidc_user: 'alice@example.com' } }),
			ubus_mod.get_session({ ubus: ub, log: make_log() }, SID));
	});
});

// ─── destroy_session ─────────────────────────────────────────────────────────

describe('ubus: destroy_session', () => {
	it('returns UBUS_UNAVAILABLE when deps.ubus is null', () => {
		assert.match(contains({ ok: false, error: 'UBUS_UNAVAILABLE' }),
			ubus_mod.destroy_session({ ubus: null, log: make_log() }, SID));
	});

	it('returns INVALID_SID for null', () => {
		assert.match(contains({ ok: false, error: 'INVALID_SID' }),
			ubus_mod.destroy_session({ ubus: make_ubus(), log: make_log() }, null));
	});

	it('returns UBUS_ERROR when the destroy call fails', () => {
		let ub = make_ubus({ 'session.destroy': { ok: false, error: 'not_found' } });
		assert.match(contains({ ok: false, error: 'UBUS_ERROR' }),
			ubus_mod.destroy_session({ ubus: ub, log: make_log() }, SID));
	});

	it('returns ok() on success', () => {
		assert.match(contains({ ok: true }),
			ubus_mod.destroy_session({ ubus: make_ubus(), log: make_log() }, SID));
	});
});

// ─── reap_stale_tokens ───────────────────────────────────────────────────────

describe('ubus: reap_stale_tokens', () => {
	it('returns ok(0) when the token directory does not exist', () => {
		let deps = { fs: { lsdir: () => null }, clock: { time: () => NOW }, log: make_log() };
		assert.match(contains({ ok: true, data: 0 }), ubus_mod.reap_stale_tokens(deps));
	});

	it('returns ok(0) when the token directory is empty', () => {
		let deps = { fs: { lsdir: () => [] }, clock: { time: () => NOW }, log: make_log() };
		assert.match(contains({ ok: true, data: 0 }), ubus_mod.reap_stale_tokens(deps));
	});

	it('does not reap files younger than 24 hours', () => {
		let deps = {
			fs: {
				lsdir:  () => ['tok1'],
				stat:   () => ({ mtime: NOW - 86399 }),
				unlink: () => null,
			},
			clock: { time: () => NOW },
			log: make_log(),
		};
		assert.match(contains({ ok: true, data: 0 }), ubus_mod.reap_stale_tokens(deps));
	});

	it('reaps files older than 24 hours', () => {
		let deps = {
			fs: {
				lsdir:  () => ['tok1', 'tok2'],
				stat:   () => ({ mtime: NOW - 86401 }),
				unlink: () => null,
			},
			clock: { time: () => NOW },
			log: make_log(),
		};
		assert.match(contains({ ok: true, data: 2 }), ubus_mod.reap_stale_tokens(deps));
	});

	it('reaps only files past the threshold when ages are mixed', () => {
		let deps = {
			fs: {
				lsdir:  () => ['old', 'new'],
				stat:   (path) => ({ mtime: path === TOK_DIR + '/old' ? NOW - 86401 : NOW - 100 }),
				unlink: () => null,
			},
			clock: { time: () => NOW },
			log: make_log(),
		};
		assert.match(contains({ ok: true, data: 1 }), ubus_mod.reap_stale_tokens(deps));
	});
});

// ─── register_token ──────────────────────────────────────────────────────────

describe('ubus: register_token', () => {
	it('returns INVALID_TOKEN for null', () => {
		assert.match(contains({ ok: false, error: 'INVALID_TOKEN' }),
			ubus_mod.register_token({ fs: { mkdir: () => false }, log: make_log() }, null));
	});

	it('returns INVALID_TOKEN for a non-string', () => {
		assert.match(contains({ ok: false, error: 'INVALID_TOKEN' }),
			ubus_mod.register_token({ fs: { mkdir: () => false }, log: make_log() }, 42));
	});

	it('returns ok() for a new token (lock directory created successfully)', () => {
		// Both mkdir calls return true; the first (ensure-dir) is ignored,
		// the second (atomic lock) determines the outcome.
		assert.match(contains({ ok: true }),
			ubus_mod.register_token({ fs: { mkdir: () => true }, log: make_log() }, 'access-token'));
	});

	it('returns TOKEN_REPLAYED when the lock directory already exists', () => {
		assert.match(contains({ ok: false, error: 'TOKEN_REPLAYED' }),
			ubus_mod.register_token({ fs: { mkdir: () => false }, log: make_log() }, 'access-token'));
	});
});

// ─── create_passwordless_session ─────────────────────────────────────────────

const PERMS_USER  = { read: ['luci-mod-network'], write: ['luci-app-firewall'] };
const PERMS_ADMIN = { read: ['*'], write: [] };

// Minimal fs that satisfies the ACL scan for non-admin (never called) and admin with empty dir.
const EMPTY_ACL_FS = { lsdir: () => [], readfile: () => null, mkdir: () => false };

function make_create_deps(ub, fs) {
	return { ubus: ub, fs: fs || EMPTY_ACL_FS, clock: { time: () => NOW }, log: make_log() };
}

describe('ubus: create_passwordless_session — guards', () => {
	it('dies with CONTRACT_VIOLATION when deps.ubus is null', () => {
		assert.throws(() => ubus_mod.create_passwordless_session(
			make_create_deps(null), 'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
		), /CONTRACT_VIOLATION/);
	});

	it('dies with CONTRACT_VIOLATION when deps.ubus has no call function', () => {
		assert.throws(() => ubus_mod.create_passwordless_session(
			make_create_deps({}), 'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
		), /CONTRACT_VIOLATION/);
	});

	it('returns UBUS_SESSION_FAILED when session creation fails', () => {
		let ub = make_ubus({ 'session.create': { ok: false, error: 'call_failed' } });
		assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }),
			ubus_mod.create_passwordless_session(
				make_create_deps(ub), 'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
			));
	});

	it('returns UBUS_SESSION_FAILED when the session response carries no sid', () => {
		let ub = make_ubus({ 'session.create': { ok: true, data: {} } });
		assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }),
			ubus_mod.create_passwordless_session(
				make_create_deps(ub), 'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
			));
	});
});

describe('ubus: create_passwordless_session — non-admin', () => {
	it('returns ok(sid) for a user with specific permissions', () => {
		let ub = make_ubus({ 'session.create': { ok: true, data: { ubus_rpc_session: SID } } });
		assert.match(contains({ ok: true, data: SID }),
			ubus_mod.create_passwordless_session(
				make_create_deps(ub), 'guest', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
			));
	});
});

describe('ubus: create_passwordless_session — admin wildcard', () => {
	it('detects wildcard in read and grants full access', () => {
		let ub = make_ubus({ 'session.create': { ok: true, data: { ubus_rpc_session: SID } } });
		assert.match(contains({ ok: true, data: SID }),
			ubus_mod.create_passwordless_session(
				make_create_deps(ub), 'root', { read: ['*'], write: [] }, 'a@e.com', 'at', 'rt', 'it'
			));
	});

	it('detects wildcard in write and grants full access', () => {
		let ub = make_ubus({ 'session.create': { ok: true, data: { ubus_rpc_session: SID } } });
		assert.match(contains({ ok: true, data: SID }),
			ubus_mod.create_passwordless_session(
				make_create_deps(ub), 'root', { read: [], write: ['*'] }, 'a@e.com', 'at', 'rt', 'it'
			));
	});

	it('returns UBUS_SESSION_FAILED and destroys the session when ACL scan fails', () => {
		let ub = make_ubus({ 'session.create': { ok: true, data: { ubus_rpc_session: SID } } });
		// lsdir returns null → ACL_SCAN_FAILED → session must be destroyed
		let bad_fs = { lsdir: () => null, readfile: () => null };
		let res = ubus_mod.create_passwordless_session(
			make_create_deps(ub, bad_fs), 'root', PERMS_ADMIN, 'a@e.com', 'at', 'rt', 'it'
		);
		assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }), res);
		let destroys = filter(ub.calls(), (c) => c.method === 'destroy');
		assert.match(1, length(destroys));
	});
});

describe('ubus: create_passwordless_session — CSPRNG failure', () => {
	afterEach(() => { crypto.set_native(null); });

	it('returns CRYPTO_INIT_FAILED when CSPRNG fails', () => {
		crypto.set_native(broken_random);
		let ub = make_ubus({ 'session.create': { ok: true, data: { ubus_rpc_session: SID } } });
		assert.match(contains({ ok: false, error: 'CRYPTO_INIT_FAILED' }),
			ubus_mod.create_passwordless_session(
				make_create_deps(ub), 'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
			));
	});
});

// ─── _grant_all_luci_acls (tested via admin session) ─────────────────────────

describe('ubus: _grant_all_luci_acls', () => {
	// Runs an admin session and returns the access-group grant calls made.
	function acl_grants_for(lsdir_fn, readfile_fn) {
		let ub = make_ubus({ 'session.create': { ok: true, data: { ubus_rpc_session: SID } } });
		let fs = {
			lsdir:   lsdir_fn   || (() => []),
			readfile: readfile_fn || (() => null),
			mkdir:   () => false,
		};
		ubus_mod.create_passwordless_session(
			{ ubus: ub, fs, clock: { time: () => NOW }, log: make_log() },
			'root', PERMS_ADMIN, 'a@e.com', 'at', 'rt', 'it'
		);
		return filter(ub.calls(), (c) => c.method === 'grant' && c.params.scope === 'access-group');
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
		let reads  = filter(grants, (c) => c.params.objects[0][1] === 'read');
		let writes = filter(grants, (c) => c.params.objects[0][1] === 'write');
		assert.match(1, length(reads));
		assert.match(1, length(writes));
		assert.match('luci-base', reads[0].params.objects[0][0]);
	});
});
