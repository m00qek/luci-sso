import { describe, it, assert, contains, mock, spy } from 'utest';
import * as ubus_mod from 'luci_sso.ubus';
import * as Result from 'luci_sso.result';
import * as native from 'luci_sso.native';
import { mock_ubus_channel, UBUS_NO_DATA } from 'context';

const SID     = 'aabbccdd11223344aabbccdd11223344';
const ACL_DIR = '/usr/share/rpcd/acl.d';

// Wraps proxies into the deps shape expected by ubus.uc. deps.ubus is the
// production channel (see context.uc mock_ubus_channel): a mocked null reply is
// a failed call (UBUS_ERROR), UBUS_NO_DATA is rpcd's empty success.
function build_deps(proxies) {
	let deps = { log: () => null };
	if (proxies.ubus) {
		let conn = proxies.ubus.connect();
		deps._ubus_conn = conn;
		deps.ubus = mock_ubus_channel(conn);
	}
	if (proxies.fs)     deps.fs     = proxies.fs;
	if (proxies.clock)  deps.clock  = proxies.clock;
	if (proxies.uci)    deps.uci    = proxies.uci.cursor();
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
		mock.inject_all({ ubus: { strict: true, data: { "session:destroy": UBUS_NO_DATA } } }, (proxies) => {
			assert.match(contains({ ok: true }),
				ubus_mod.destroy_session(build_deps(proxies), SID));
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

// A small, realistic acl.d: luci-base is defined across two files (as
// unauthenticated is in OpenWrt), luci-mod-system-reboot has only a write
// section, other-app is not a luci-* group, and broken.json does not parse.
const ACL_FILES = {
	'luci-base.json': sprintf('%J', {
		'luci-base': { read: { ubus: { luci: [ 'getVersion' ] }, uci: [ 'luci' ] }, write: { uci: [ 'luci' ] } },
	}),
	'luci-mod-system.json': sprintf('%J', {
		'luci-mod-system-config': {
			description: 'System',
			read:  { ubus: { system: [ 'info' ] }, uci: [ 'system' ] },
			write: { ubus: { rc: [ 'init' ] }, uci: [ 'system' ], file: { '/etc/banner': [ 'write' ] } },
		},
		'luci-mod-system-reboot': { write: { ubus: { system: [ 'reboot' ] } } },
	}),
	'luci-zz-extra.json': sprintf('%J', {
		'luci-base': { read: { file: { '/etc/openwrt_release': [ 'read' ] } } },
		'other-app': { read: { uci: [ 'other' ] } },
	}),
	'broken.json': '{ not json',
};

const ACL_FS = { strict: true, behavior: {
	lsdir:    (p) => (p === ACL_DIR) ? keys(ACL_FILES) : [],
	readfile: (p) => ACL_FILES[substr(p, length(ACL_DIR) + 1)],
} };

const PERMS_USER  = { read: ['luci-base'], write: ['luci-mod-system-config'] };
const PERMS_ADMIN = { read: ['*'], write: ['*'] };

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
			ubus:   { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
			fs:     ACL_FS,
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
				"session:grant":  UBUS_NO_DATA,
				"session:set":    (args) => { token_len = length(args.values.token); return UBUS_NO_DATA; },
			} },
			fs: ACL_FS,
		}, (proxies) => {
			assert.match(contains({ ok: true, data: SID }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'guest', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
				));
			assert.match(true, token_len >= 43, 'CSRF token MUST be at least 256 bits (43+ chars)');
		});
	});
});

describe('ubus: create_passwordless_session — session set', () => {
	it('destroys the session and returns UBUS_SESSION_FAILED when session set fails', () => {
		let destroyed = null;
		mock.inject_all({
			ubus: { strict: true, data: {
				"session:create":  { ubus_rpc_session: SID },
				"session:grant":   UBUS_NO_DATA,
				"session:set":     () => null,
				"session:destroy": (args) => { destroyed = args.ubus_rpc_session; return UBUS_NO_DATA; },
			} },
			fs: ACL_FS,
		}, (proxies) => {
			assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'guest', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
				));
			assert.match(SID, destroyed, 'the half-initialised session must be destroyed');
		});
	});
});

// Captures the timeout passed to `session create`; the rest of the flow succeeds.
function created_timeout(uci_spec) {
	let seen = null;
	let spec = {
		ubus: { strict: true, data: {
			"session:create": (args) => { seen = args.timeout; return { ubus_rpc_session: SID }; },
			"session:grant":  UBUS_NO_DATA,
			"session:set":    UBUS_NO_DATA,
		} },
		fs: ACL_FS,
	};
	if (uci_spec) spec.uci = uci_spec;
	mock.inject_all(spec, (proxies) => {
		let res = ubus_mod.create_passwordless_session(
			build_deps(proxies), 'guest', PERMS_USER, 'u@e.com', 'at', 'rt', 'it');
		assert.match(contains({ ok: true, data: SID }), res);
	});
	return seen;
}

function luci_uci(sessiontime) {
	let sauth = { ".type": "internal" };
	if (sessiontime != null) sauth.sessiontime = sessiontime;
	return { strict: true, data: { luci: { sauth } } };
}

describe('ubus: create_passwordless_session — session timeout', () => {
	it("uses LuCI's luci.sauth.sessiontime, as LuCI's own password login does", () => {
		assert.match(7200, created_timeout(luci_uci("7200")));
	});

	it('falls back to 3600 when the option is missing', () => {
		assert.match(3600, created_timeout(luci_uci(null)));
	});

	it('falls back to 3600 when the option is not a positive integer', () => {
		assert.match(3600, created_timeout(luci_uci("0")));
		assert.match(3600, created_timeout(luci_uci("-5")));
		assert.match(3600, created_timeout(luci_uci("forever")));
	});

	it('falls back to 3600 when uci is not available', () => {
		assert.match(3600, created_timeout(null));
	});
});

// Every grant a session receives for `perms`, flattened to sorted
// "scope object function" strings.
function grants_for(perms, fs_spec, logs) {
	let out = null;
	mock.inject_all({
		ubus: { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } },
		fs:   fs_spec || ACL_FS,
	}, (proxies) => {
		let deps = build_deps(proxies);
		if (logs) deps.log = (l, m) => push(logs, m);
		assert.match(contains({ ok: true, data: SID }),
			ubus_mod.create_passwordless_session(deps, 'root', perms, 'a@e.com', 'at', 'rt', 'it'));
		out = [];
		for (let c in filter(spy(deps._ubus_conn).calls.call, (c) => c[1] === 'grant'))
			for (let o in c[2].objects)
				push(out, `${c[2].scope} ${o[0]} ${o[1]}`);
		out = sort(out);
	});
	return out;
}

// Expected expansions of the fixture's sections (rpcd's rules).
const BASE_READ = [ 'access-group luci-base read', 'file /etc/openwrt_release read', 'ubus luci getVersion', 'uci luci read' ];
const BASE_WRITE = [ 'access-group luci-base write', 'uci luci write' ];
const SYS_READ = [ 'access-group luci-mod-system-config read', 'ubus system info', 'uci system read' ];
const SYS_WRITE = [ 'access-group luci-mod-system-config write', 'file /etc/banner write', 'ubus rc init', 'uci system write' ];
const REBOOT_WRITE = [ 'access-group luci-mod-system-reboot write', 'ubus system reboot' ];
const RAW = [ 'cgi-io * *', 'file * *', 'uci * *', 'ubus * *' ];

describe('ubus: create_passwordless_session — access-group expansion (rpcd rules)', () => {
	it('a read group gets its read sections from every file that defines it', () => {
		assert.match(sort(BASE_READ), grants_for({ read: ['luci-base'], write: [] }));
	});

	it('a write group gets its write section and, as write implies read, its read section', () => {
		assert.match(sort([ ...SYS_READ, ...SYS_WRITE ]), grants_for({ read: [], write: ['luci-mod-system-config'] }));
	});

	it('a write-only group grants nothing on read', () => {
		assert.match([], grants_for({ read: ['luci-mod-system-reboot'], write: [] }));
		assert.match(sort(REBOOT_WRITE), grants_for({ read: [], write: ['luci-mod-system-reboot'] }));
	});

	it("read '*' expands every luci-* group's read section, and only luci-* groups", () => {
		assert.match(sort([ ...BASE_READ, ...SYS_READ ]), grants_for({ read: ['*'], write: [] }));
	});

	it('a mixed role: read everything, write one group', () => {
		assert.match(sort([ ...BASE_READ, ...SYS_READ, ...SYS_WRITE ]),
			grants_for({ read: ['*'], write: ['luci-mod-system-config'] }));
	});

	it('globs and negations follow fnmatch, negations first', () => {
		assert.match(sort([ ...SYS_READ ]), grants_for({ read: ['luci-mod-system-*'], write: [] }));
		assert.match(sort([ ...BASE_READ ]), grants_for({ read: ['*', '!luci-mod-*'], write: [] }));
		assert.match(sort([ ...BASE_READ ]), grants_for({ read: ['luci-?ase'], write: [] }));
		// Like rpcd: whitespace after '!' is skipped; trailing whitespace is
		// part of the pattern, so it matches nothing and denies nothing.
		assert.match(sort([ ...BASE_READ ]), grants_for({ read: ['*', '!  luci-mod-*'], write: [] }));
		assert.match(sort([ ...BASE_READ, ...SYS_READ ]), grants_for({ read: ['*', '!luci-mod-* '], write: [] }));
	});

	it('a non-luci group is reachable by exact name only, never by a wildcard', () => {
		assert.match([ 'access-group other-app read', 'uci other read' ], grants_for({ read: ['other-app'], write: [] }));
		assert.match(-1, index(grants_for({ read: ['*'], write: [] }), 'uci other read'));
	});

	it('every non-admin session also reads the unauthenticated group, which LuCI needs', () => {
		let files = { ...ACL_FILES, 'unauthenticated.json': sprintf('%J', {
			'unauthenticated': { read: { ubus: { session: [ 'access', 'login' ], luci: [ 'getFeatures' ] } } },
		}) };
		let fs = { strict: true, behavior: {
			lsdir: (p) => (p === ACL_DIR) ? keys(files) : [],
			readfile: (p) => files[substr(p, length(ACL_DIR) + 1)],
		} };
		let base = [ 'access-group unauthenticated read', 'ubus luci getFeatures', 'ubus session access', 'ubus session login' ];
		assert.match(sort([ ...BASE_READ, ...base ]), grants_for({ read: ['luci-base'], write: [] }, fs));
		assert.match(sort([ ...base ]), grants_for({ read: [], write: [] }, fs), 'even a role with no lists');
	});

	it('an unknown group is logged and grants nothing', () => {
		let logs = [];
		assert.match([], grants_for({ read: ['luci-nope'], write: [] }, null, logs));
		assert.match(1, length(filter(logs, (m) => index(m, "unknown access group 'luci-nope'") >= 0)));
	});

	it('skips malformed files, non-object groups and sections, and non-string entries', () => {
		let files = {
			'a.json': sprintf('%J', {
				'luci-x': { read: { uci: [ 'ok', 42, null ], ubus: { o: [ 'f', 7 ], bad: 'nope' }, junk: 5 }, write: 'not-an-object' },
				'luci-y': 'not-an-object',
			}),
			'b.json': '[ "luci-z" ]',
			'c.json': '{ broken',
			'readme.txt': '{"luci-t":{"read":{"uci":["t"]}}}',
		};
		let fs = { strict: true, behavior: {
			lsdir: (p) => (p === ACL_DIR) ? keys(files) : [],
			readfile: (p) => files[substr(p, length(ACL_DIR) + 1)],
		} };
		assert.match(sort([ 'access-group luci-x read', 'uci ok read', 'ubus o f' ]), grants_for({ read: ['*'], write: ['luci-x'] }, fs));
	});
});

describe('ubus: create_passwordless_session — full admin', () => {
	it("write '*' is full admin: raw grants plus read and write on every luci-* group, unchanged", () => {
		let all = [ 'luci-base', 'luci-mod-system-config', 'luci-mod-system-reboot' ];
		let expected = [ ...RAW ];
		for (let m in [ 'read', 'write' ]) for (let g in all) push(expected, `access-group ${g} ${m}`);
		assert.match(sort(expected), grants_for({ read: [], write: ['*'] }));
		assert.match(sort(expected), grants_for(PERMS_ADMIN));
	});

	it('returns UBUS_SESSION_FAILED and destroys the session when the ACL scan fails, for any role', () => {
		for (let perms in [ PERMS_ADMIN, { read: ['*'], write: [] }, PERMS_USER ]) {
			mock.inject_all({
				ubus:   { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": UBUS_NO_DATA, "session:destroy": UBUS_NO_DATA } },
				fs:     { strict: true, behavior: { lsdir: () => null } },
			}, (proxies) => {
				let deps = build_deps(proxies);
				assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }),
					ubus_mod.create_passwordless_session(deps, 'root', perms, 'a@e.com', 'at', 'rt', 'it'));
				assert.match(1, length(filter(spy(deps._ubus_conn).calls.call, (c) => c[1] === 'destroy')));
				assert.match(0, length(filter(spy(deps._ubus_conn).calls.call, (c) => c[1] === 'grant')));
			});
		}
	});
});

describe('ubus: create_passwordless_session — CSPRNG failure', () => {
	it('returns CRYPTO_INIT_FAILED when CSPRNG fails', () => {
		mock.inject_all({
			ubus:   { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": UBUS_NO_DATA } },
			native: { strict: true, behavior: { random: () => null } },
			fs:     ACL_FS,
		}, (proxies) => {
			assert.match(contains({ ok: false, error: 'CRYPTO_INIT_FAILED' }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'root', PERMS_USER, 'u@e.com', 'at', 'rt', 'it'
				));
		});
	});
});

