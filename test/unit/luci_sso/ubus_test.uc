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

function acl_fs(files) {
	return { strict: true, behavior: {
		lsdir:    (p) => (p === ACL_DIR) ? keys(files) : [],
		readfile: (p) => files[substr(p, length(ACL_DIR) + 1)],
	} };
}

const ACL_FS = acl_fs(ACL_FILES);

// The rpcd login entry the luci-sso ubus object writes for a role.
function login(role, read, write) {
	return { '.type': 'login', username: `sso:${role}`, read, write };
}

// UCI with LuCI's session time and the given rpcd sections.
function rpcd_uci(sections) {
	return { strict: true, data: { luci: { sauth: { '.type': 'internal', sessiontime: '3600' } }, rpcd: sections } };
}

const USER_UCI = rpcd_uci({ luci_sso_guest: login('guest', [ 'luci-base' ], [ 'luci-mod-system-config' ]) });

const OK_UBUS = { strict: true, data: { "session:create": { ubus_rpc_session: SID }, "session:grant": UBUS_NO_DATA, "session:set": UBUS_NO_DATA } };

describe('ubus: create_passwordless_session — guards', () => {
	it('dies with CONTRACT_VIOLATION when deps.ubus is null', () => {
		assert.throws(() => ubus_mod.create_passwordless_session(
			{ ubus: null, fs: null, clock: null, log: () => null },
			'guest', 'u@e.com', 'at', 'rt', 'it'
		), /CONTRACT_VIOLATION/);
	});

	it('dies with CONTRACT_VIOLATION when deps.ubus has no call function', () => {
		assert.throws(() => ubus_mod.create_passwordless_session(
			{ ubus: {}, fs: null, clock: null, log: () => null },
			'guest', 'u@e.com', 'at', 'rt', 'it'
		), /CONTRACT_VIOLATION/);
	});

	it('dies with CONTRACT_VIOLATION when deps.uci is missing', () => {
		mock.inject_all({ ubus: { strict: true } }, (proxies) => {
			assert.throws(() => ubus_mod.create_passwordless_session(
				build_deps(proxies), 'guest', 'u@e.com', 'at', 'rt', 'it'
			), /CONTRACT_VIOLATION/);
		});
	});

	it('dies with CONTRACT_VIOLATION when the role is not a non-empty string', () => {
		mock.inject_all({ ubus: { strict: true }, uci: USER_UCI }, (proxies) => {
			for (let role in [ null, '', 42 ])
				assert.throws(() => ubus_mod.create_passwordless_session(
					build_deps(proxies), role, 'u@e.com', 'at', 'rt', 'it'
				), /CONTRACT_VIOLATION/);
		});
	});

	it('returns UBUS_SESSION_FAILED when session creation fails', () => {
		mock.inject_all({ ubus: { strict: true, data: { "session:create": () => null } }, fs: ACL_FS, uci: USER_UCI }, (proxies) => {
			assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'guest', 'u@e.com', 'at', 'rt', 'it'
				));
		});
	});

	it('returns UBUS_SESSION_FAILED when the session response carries no sid', () => {
		mock.inject_all({
			ubus:   { strict: true, data: { "session:create": {} } },
			fs:     ACL_FS,
			uci:    USER_UCI,
		}, (proxies) => {
			assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'guest', 'u@e.com', 'at', 'rt', 'it'
				));
		});
	});
});

// Runs create_passwordless_session for `role` against the given rpcd
// sections; returns { res, calls, logs }, where calls are the ubus calls made.
function attempt(role, sections, fs_spec) {
	let out = null;
	mock.inject_all({ ubus: OK_UBUS, fs: fs_spec || ACL_FS, uci: rpcd_uci(sections) }, (proxies) => {
		let deps = build_deps(proxies), logs = [];
		deps.log = (l, m) => push(logs, m);
		let res = ubus_mod.create_passwordless_session(deps, role, 'u@e.com', 'at', 'rt', 'it');
		out = { res, calls: spy(deps._ubus_conn).calls.call || [], logs };
	});
	return out;
}

describe('ubus: create_passwordless_session — the role\'s rpcd login entry', () => {
	it('returns MISSING_RPCD_LOGIN, and creates no session, when the role has no entry', () => {
		// A stock root login does not stand in for a role named root.
		let a = attempt('root', { root_login: { '.type': 'login', username: 'root', password: '$p$root', read: [ '*' ], write: [ '*' ] } });
		assert.match(contains({ ok: false, error: 'MISSING_RPCD_LOGIN' }), a.res);
		assert.match(0, length(a.calls), 'no session is created');
		assert.match(1, length(filter(a.logs, (m) => index(m, "MISSING_RPCD_LOGIN: role 'root' has no rpcd login entry 'luci_sso_root'") == 0)));
	});

	it('returns MISSING_RPCD_LOGIN when the entry is not a login or names another user', () => {
		let not_login = { ...login('guest', [ '*' ], []), '.type': 'rpcd' };
		assert.match(contains({ ok: false, error: 'MISSING_RPCD_LOGIN' }), attempt('guest', { luci_sso_guest: not_login }).res);
		let other_user = { ...login('guest', [ '*' ], []), username: 'root' };
		assert.match(contains({ ok: false, error: 'MISSING_RPCD_LOGIN' }), attempt('guest', { luci_sso_guest: other_user }).res);
		let no_user = login('guest', [ '*' ], []);
		delete no_user.username;
		assert.match(contains({ ok: false, error: 'MISSING_RPCD_LOGIN' }), attempt('guest', { luci_sso_guest: no_user }).res);
	});

	it('returns INSECURE_RPCD_LOGIN, and creates no session, when the entry has a password option, even an empty one', () => {
		for (let pw in [ '$p$root', '' ]) {
			let a = attempt('guest', { luci_sso_guest: { ...login('guest', [ '*' ], []), password: pw } });
			assert.match(contains({ ok: false, error: 'INSECURE_RPCD_LOGIN' }), a.res);
			assert.match(0, length(a.calls), 'no session is created');
			assert.match(1, length(filter(a.logs, (m) => index(m, "INSECURE_RPCD_LOGIN: rpcd login entry 'luci_sso_guest'") == 0)));
		}
	});

	it("names the session sso:<role>, the entry's username, so rpcd rebuilds it from the entry on reload", () => {
		let a = attempt('guest', { luci_sso_guest: login('guest', [ 'luci-base' ], []) });
		assert.match(contains({ ok: true, data: SID }), a.res);
		let set = filter(a.calls, (c) => c[1] === 'set')[0];
		assert.match('sso:guest', set[2].values.username);
	});

	it('reads single-value options as one-entry lists and missing ones as empty', () => {
		let a = attempt('guest', { luci_sso_guest: { '.type': 'login', username: 'sso:guest', read: 'luci-base' } });
		assert.match(contains({ ok: true }), a.res);
		assert.match(true, length(filter(a.calls, (c) => c[1] === 'grant')) > 0);
	});

	it('returns UBUS_SESSION_FAILED, and creates no session, when the ACL scan fails', () => {
		let a = attempt('guest', { luci_sso_guest: login('guest', [ '*' ], [ '*' ]) }, { strict: true, behavior: { lsdir: () => null } });
		assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }), a.res);
		assert.match(0, length(a.calls));
	});
});

describe('ubus: create_passwordless_session — session values', () => {
	it('returns ok(sid) and sets the OIDC values and a CSRF token of at least 256 bits (43+ base64url chars) (B3)', () => {
		let values = null;
		mock.inject_all({
			ubus: { strict: true, data: {
				"session:create": { ubus_rpc_session: SID },
				"session:grant":  UBUS_NO_DATA,
				"session:set":    (args) => { values = args.values; return UBUS_NO_DATA; },
			} },
			fs: ACL_FS,
			uci: USER_UCI,
		}, (proxies) => {
			assert.match(contains({ ok: true, data: SID }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'guest', 'u@e.com', 'at', 'rt', 'it'
				));
			assert.match(contains({ username: 'sso:guest', oidc_user: 'u@e.com', oidc_access_token: 'at',
				oidc_refresh_token: 'rt', oidc_id_token: 'it' }), values);
			assert.match(true, length(values.token) >= 43, 'CSRF token MUST be at least 256 bits (43+ chars)');
		});
	});

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
			uci: USER_UCI,
		}, (proxies) => {
			assert.match(contains({ ok: false, error: 'UBUS_SESSION_FAILED' }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'guest', 'u@e.com', 'at', 'rt', 'it'
				));
			assert.match(SID, destroyed, 'the half-initialised session must be destroyed');
		});
	});
});

// Captures the timeout passed to `session create`; the rest of the flow succeeds.
function created_timeout(sessiontime) {
	let seen = null;
	let sauth = { ".type": "internal" };
	if (sessiontime != null) sauth.sessiontime = sessiontime;
	mock.inject_all({
		ubus: { strict: true, data: {
			"session:create": (args) => { seen = args.timeout; return { ubus_rpc_session: SID }; },
			"session:grant":  UBUS_NO_DATA,
			"session:set":    UBUS_NO_DATA,
		} },
		fs: ACL_FS,
		uci: { strict: true, data: { luci: { sauth }, rpcd: { luci_sso_guest: login('guest', [ 'luci-base' ], []) } } },
	}, (proxies) => {
		let res = ubus_mod.create_passwordless_session(
			build_deps(proxies), 'guest', 'u@e.com', 'at', 'rt', 'it');
		assert.match(contains({ ok: true, data: SID }), res);
	});
	return seen;
}

describe('ubus: create_passwordless_session — session timeout', () => {
	it("uses LuCI's luci.sauth.sessiontime, as LuCI's own password login does", () => {
		assert.match(7200, created_timeout("7200"));
	});

	it('falls back to 3600 when the option is missing', () => {
		assert.match(3600, created_timeout(null));
	});

	it('falls back to 3600 when the option is not a positive integer', () => {
		assert.match(3600, created_timeout("0"));
		assert.match(3600, created_timeout("-5"));
		assert.match(3600, created_timeout("forever"));
	});
});

// Every grant a session receives for an entry with the given lists, flattened
// to sorted "scope object function" strings.
function grants_for(perms, fs_spec, logs) {
	let out = null;
	mock.inject_all({
		ubus: OK_UBUS,
		fs:   fs_spec || ACL_FS,
		uci:  rpcd_uci({ luci_sso_r: login('r', perms.read, perms.write) }),
	}, (proxies) => {
		let deps = build_deps(proxies);
		if (logs) deps.log = (l, m) => push(logs, m);
		assert.match(contains({ ok: true, data: SID }),
			ubus_mod.create_passwordless_session(deps, 'r', 'a@e.com', 'at', 'rt', 'it'));
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
const OTHER_READ = [ 'access-group other-app read', 'uci other read' ];

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

	it("read '*' expands every group's read section, LuCI's or not, as in rpcd", () => {
		assert.match(sort([ ...BASE_READ, ...SYS_READ, ...OTHER_READ ]), grants_for({ read: ['*'], write: [] }));
	});

	it('a mixed role: read everything, write one group', () => {
		assert.match(sort([ ...BASE_READ, ...SYS_READ, ...OTHER_READ, ...SYS_WRITE ]),
			grants_for({ read: ['*'], write: ['luci-mod-system-config'] }));
	});

	it("read '*' and write '*' is exactly every group's expansion: no raw grants", () => {
		assert.match(sort([ ...BASE_READ, ...BASE_WRITE, ...SYS_READ, ...SYS_WRITE, ...REBOOT_WRITE, ...OTHER_READ ]),
			grants_for({ read: ['*'], write: ['*'] }));
		assert.match(grants_for({ read: ['*'], write: ['*'] }), grants_for({ read: [], write: ['*'] }), 'write implies read');
	});

	it('globs and negations follow fnmatch, negations first', () => {
		assert.match(sort([ ...SYS_READ ]), grants_for({ read: ['luci-mod-system-*'], write: [] }));
		assert.match(sort([ ...BASE_READ, ...OTHER_READ ]), grants_for({ read: ['*', '!luci-mod-*'], write: [] }));
		assert.match(sort([ ...BASE_READ ]), grants_for({ read: ['luci-?ase'], write: [] }));
		assert.match(sort([ ...BASE_READ, ...SYS_READ ]), grants_for({ read: ['luci-[a-z]*'], write: [] }));
		// Like rpcd: whitespace after '!' is skipped; trailing whitespace is
		// part of the pattern, so it matches nothing and denies nothing.
		assert.match(sort([ ...BASE_READ, ...OTHER_READ ]), grants_for({ read: ['*', '!  luci-mod-*'], write: [] }));
		assert.match(sort([ ...BASE_READ, ...SYS_READ, ...OTHER_READ ]), grants_for({ read: ['*', '!luci-mod-* '], write: [] }));
	});

	it('a non-luci group is matched by name and by wildcard alike', () => {
		assert.match(sort(OTHER_READ), grants_for({ read: ['other-app'], write: [] }));
		assert.match(sort(OTHER_READ), grants_for({ read: ['other-*'], write: [] }));
	});

	it('grants nothing a list does not name: no unauthenticated baseline', () => {
		let files = { ...ACL_FILES, 'unauthenticated.json': sprintf('%J', {
			'unauthenticated': { read: { ubus: { session: [ 'access', 'login' ], luci: [ 'getFeatures' ] } } },
		}) };
		let unauth = [ 'access-group unauthenticated read', 'ubus luci getFeatures', 'ubus session access', 'ubus session login' ];
		assert.match(sort(BASE_READ), grants_for({ read: ['luci-base'], write: [] }, acl_fs(files)));
		assert.match([], grants_for({ read: [], write: [] }, acl_fs(files)), 'an entry with no lists grants nothing');
		assert.match(sort([ ...BASE_READ, ...unauth ]), grants_for({ read: ['luci-base', 'unauthenticated'], write: [] }, acl_fs(files)),
			'the group is granted when the entry names it');
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
		assert.match(sort([ 'access-group luci-x read', 'uci ok read', 'ubus o f' ]), grants_for({ read: ['*'], write: ['luci-x'] }, acl_fs(files)));
	});
});

describe('ubus: create_passwordless_session — CSPRNG failure', () => {
	it('destroys the session and returns CRYPTO_INIT_FAILED when CSPRNG fails', () => {
		let destroyed = null;
		mock.inject_all({
			ubus:   { strict: true, data: {
				"session:create":  { ubus_rpc_session: SID },
				"session:grant":   UBUS_NO_DATA,
				"session:destroy": (args) => { destroyed = args.ubus_rpc_session; return UBUS_NO_DATA; },
			} },
			native: { strict: true, behavior: { random: () => null } },
			fs:     ACL_FS,
			uci:    USER_UCI,
		}, (proxies) => {
			assert.match(contains({ ok: false, error: 'CRYPTO_INIT_FAILED' }),
				ubus_mod.create_passwordless_session(
					build_deps(proxies), 'guest', 'u@e.com', 'at', 'rt', 'it'
				));
			assert.match(SID, destroyed, 'a session without a CSRF token must be destroyed');
		});
	});
});
