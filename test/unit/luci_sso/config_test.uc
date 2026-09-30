import { describe, it, prop, gen, assert, contains, mock } from 'utest';
import * as config from 'luci_sso.config';

// config.load / config.is_enabled read UCI via the injected `uci` proxy.
const OIDC = {
	".type": "oidc", enabled: "1",
	issuer_url: "https://idp.com", client_id: "c1", client_secret: "s1",
	redirect_uri: "https://r1/callback", clock_tolerance: "300",
};
const ROLE = { ".type": "role", email: "admin@test.com" };

function load_sections(sections, logs) {
	let res;
	mock.inject('uci', { data: { "luci-sso": sections } }, (uci) => {
		res = config.load({ uci: uci.cursor(), log: (l, m) => logs ? push(logs, [ l, m ]) : null });
	});
	return res;
}

function is_enabled_sections(sections) {
	let res;
	mock.inject('uci', { data: { "luci-sso": sections } }, (uci) => {
		res = config.is_enabled({ uci: uci.cursor(), log: () => null });
	});
	return res;
}

const ROLE_READERS = {
	name: 'readers',
	emails: ['alice@example.com'],
	groups: []
};

const ROLE_WRITERS = {
	name: 'writers',
	emails: [],
	groups: ['developers']
};

const ROLE_ADMIN = {
	name: 'admin',
	emails: ['admin@example.com'],
	groups: ['admins']
};

// ─── find_role_for_user ──────────────────────────────────────────────────────

describe('config: find_role_for_user', () => {
	it('returns NO_ROLES_MATCHED when no roles are configured', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_role_for_user({ roles: [] }, { email: 'alice@example.com' }));
	});

	it('returns NO_ROLES_MATCHED when email does not match any role', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_role_for_user({ roles: [ROLE_ADMIN] }, { email: 'stranger@example.com' }));
	});

	it('returns NO_ROLES_MATCHED when group does not match any role', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_role_for_user({ roles: [ROLE_ADMIN] }, { groups: ['nobody'] }));
	});

	it('matches by email and returns the role name only', () => {
		let res = config.find_role_for_user({ roles: [ROLE_READERS] }, { email: 'alice@example.com', email_verified: true });
		assert.match({ ok: true, data: { role_name: 'readers', also_matched: [] } }, res);
	});

	it('email matching is case-insensitive', () => {
		let res = config.find_role_for_user({ roles: [ROLE_READERS] }, { email: 'ALICE@EXAMPLE.COM', email_verified: true });
		assert.match(contains({ ok: true, data: { role_name: 'readers' } }), res);
	});

	it('matches by group', () => {
		let res = config.find_role_for_user({ roles: [ROLE_WRITERS] }, { groups: ['developers'] });
		assert.match(contains({ ok: true, data: { role_name: 'writers' } }), res);
	});

	it('treats non-array claims.groups as empty', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_role_for_user({ roles: [ROLE_WRITERS] }, { groups: 'developers' }));
	});

	it('the first matching role in config order wins, and the others are listed in order', () => {
		let claims = { email: 'alice@example.com', email_verified: true, groups: ['developers', 'admins'] };
		assert.match({ ok: true, data: { role_name: 'readers', also_matched: [ 'writers', 'admin' ] } },
			config.find_role_for_user({ roles: [ROLE_READERS, ROLE_WRITERS, ROLE_ADMIN] }, claims));
		assert.match({ ok: true, data: { role_name: 'admin', also_matched: [ 'writers', 'readers' ] } },
			config.find_role_for_user({ roles: [ROLE_ADMIN, ROLE_WRITERS, ROLE_READERS] }, claims));
	});

	it('roles that do not match are neither chosen nor listed', () => {
		let res = config.find_role_for_user({ roles: [ROLE_ADMIN, ROLE_WRITERS, ROLE_READERS] }, { email: 'alice@example.com', email_verified: true });
		assert.match({ ok: true, data: { role_name: 'readers', also_matched: [] } }, res);
	});

	it('matches admin by group when no email is provided', () => {
		let res = config.find_role_for_user({ roles: [ROLE_ADMIN] }, { groups: ['admins'] });
		assert.match(contains({ ok: true, data: { role_name: 'admin' } }), res);
	});

	it('email match succeeds even when the claims group does not match the role', () => {
		let res = config.find_role_for_user({ roles: [ROLE_ADMIN] }, { email: 'admin@example.com', email_verified: true, groups: ['not-admins'] });
		assert.match(contains({ ok: true, data: { role_name: 'admin' } }), res);
	});

	it('group match succeeds even when the claims email does not match the role', () => {
		let res = config.find_role_for_user({ roles: [ROLE_ADMIN] }, { email: 'other@example.com', groups: ['admins'] });
		assert.match(contains({ ok: true, data: { role_name: 'admin' } }), res);
	});

	// Whatever the claims, the chosen role is the first matching one in config
	// order, and also_matched is exactly the rest of the matches, in order.
	prop('the chosen role is always the first match in config order',
		gen.array(gen.bool(), { min_len: 1, max_len: 8 }),
		(matches) => {
			let roles = [];
			for (let i = 0; i < length(matches); i++)
				push(roles, { name: `r${i}`, emails: [ matches[i] ? 'alice@example.com' : 'bob@example.com' ], groups: [] });
			let expected = [];
			for (let i = 0; i < length(matches); i++) if (matches[i]) push(expected, `r${i}`);

			let res = config.find_role_for_user({ roles }, { email: 'alice@example.com', email_verified: true });
			if (!length(expected))
				assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }), res);
			else
				assert.match({ ok: true, data: { role_name: expected[0], also_matched: slice(expected, 1) } }, res);
		}
	);
});

// ─── find_role_for_user: sub ─────────────────────────────────────────────────

describe('config: find_role_for_user — sub', () => {
	const SUB = '248289761001';
	const ROLE_SUB = { name: 'bysub', emails: [], groups: [], subs: [ SUB ] };

	it('matches by an exact sub', () => {
		assert.match({ ok: true, data: { role_name: 'bysub', also_matched: [] } },
			config.find_role_for_user({ roles: [ROLE_SUB] }, { sub: SUB }));
	});

	it('matches by sub whatever the email says: unverified, missing or someone else\'s', () => {
		for (let claims in [
			{ sub: SUB, email: 'x@test.com', email_verified: false },
			{ sub: SUB },
			{ sub: SUB, email: 'stranger@example.com', email_verified: true },
		])
			assert.match(contains({ ok: true, data: { role_name: 'bysub' } }),
				config.find_role_for_user({ roles: [ROLE_SUB] }, claims), sprintf('%J', claims));
	});

	it('compares the sub case-sensitively: a sub that differs only in case is refused', () => {
		let role = { name: 'r', emails: [], groups: [], subs: [ 'AbC-12' ] };
		for (let sub in [ 'abc-12', 'ABC-12', 'Abc-12' ])
			assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
				config.find_role_for_user({ roles: [role] }, { sub }), sub);
		assert.match(true, config.find_role_for_user({ roles: [role] }, { sub: 'AbC-12' }).ok);
	});

	it('compares the whole sub: no prefix, suffix, whitespace or pattern match', () => {
		for (let sub in [ '24828976100', '2482897610011', ` ${SUB}`, `${SUB} `, `${SUB}\n`, '*', '.*' ])
			assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
				config.find_role_for_user({ roles: [ROLE_SUB] }, { sub }), sprintf('%J', sub));
		let glob = { name: 'glob', emails: [], groups: [], subs: [ '*' ] };
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_role_for_user({ roles: [glob] }, { sub: SUB }), 'a role sub is not a pattern');
	});

	it('refuses a sub that is not a non-empty string (OIDC Core §2)', () => {
		let roles = [
			{ name: 'num', emails: [], groups: [], subs: [ '248289761001' ] },
			{ name: 'empty', emails: [], groups: [], subs: [ '' ] },
			{ name: 'bool', emails: [], groups: [], subs: [ 'true' ] },
		];
		for (let sub in [ 248289761001, '', null, true, [ '248289761001' ], { v: '248289761001' } ])
			assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
				config.find_role_for_user({ roles }, { sub }), sprintf('%J', sub));
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }), config.find_role_for_user({ roles }, {}), 'no sub claim');
	});

	it('the first matching role in config order wins, whether it matches by sub, email or group', () => {
		let claims = { sub: SUB, email: 'alice@example.com', email_verified: true, groups: [ 'developers' ] };
		assert.match({ ok: true, data: { role_name: 'bysub', also_matched: [ 'readers', 'writers' ] } },
			config.find_role_for_user({ roles: [ ROLE_SUB, ROLE_READERS, ROLE_WRITERS ] }, claims));
		assert.match({ ok: true, data: { role_name: 'writers', also_matched: [ 'bysub', 'readers' ] } },
			config.find_role_for_user({ roles: [ ROLE_WRITERS, ROLE_SUB, ROLE_READERS ] }, claims));
	});

	it('a role without subs never matches by sub', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_role_for_user({ roles: [ ROLE_READERS, ROLE_WRITERS ] }, { sub: SUB }));
	});

	prop('a role matches by sub iff the claim is exactly one of its subs',
		gen.tuple(gen.elements('a', 'A', 'ab', 'aB', ''), gen.elements('a', 'A', 'ab', 'aB', '')),
		(pair, ctx) => {
			let role_sub = pair[0], claim_sub = pair[1];
			let same = (role_sub === claim_sub && length(claim_sub) > 0);
			ctx.classify('equal', same);
			let res = config.find_role_for_user({ roles: [ { name: 'r', emails: [], groups: [], subs: [ role_sub ] } ] }, { sub: claim_sub });
			assert.match(same, res.ok);
		}
	);
});

describe('config: matchable_sub', () => {
	it('returns the sub when it is a non-empty string, as written', () => {
		assert.match('Ab-12', config.matchable_sub({ sub: 'Ab-12' }));
	});

	it('returns null for an empty, missing or non-string sub', () => {
		for (let v in [ '', null, 42, true, [ 'a' ], { a: 1 } ])
			assert.match(null, config.matchable_sub({ sub: v }), sprintf('%J', v));
		assert.match(null, config.matchable_sub({}));
	});
});

// ─── find_role_for_user: email_verified (require_email_verified) ─────────────

describe('config: find_role_for_user — email_verified', () => {
	const ON = { roles: [ROLE_READERS] };
	const OFF = { roles: [ROLE_READERS], require_email_verified: false };
	let by_email = (cfg, verified) => config.find_role_for_user(cfg, { email: 'alice@example.com', email_verified: verified });

	it('an email with email_verified true matches', () => {
		assert.match(contains({ ok: true, data: { role_name: 'readers' } }), by_email(ON, true));
	});

	it('an email with email_verified false does not match', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }), by_email(ON, false));
	});

	it('an email without an email_verified claim does not match', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_role_for_user(ON, { email: 'alice@example.com' }));
	});

	it('the string "true" is not verified: the claim is a JSON boolean (OIDC Core §5.1)', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }), by_email(ON, 'true'));
	});

	it('any other value is not verified', () => {
		for (let v in [ 'false', 'TRUE', 'yes', '1', 1, [ true ], { v: true }, null ])
			assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }), by_email(ON, v), `${v}`);
	});

	it('is on when the config does not say (the default), and off only when require_email_verified is false', () => {
		assert.match(false, by_email({ roles: [ROLE_READERS] }, false).ok);
		assert.match(false, by_email({ roles: [ROLE_READERS], require_email_verified: true }, false).ok);
		assert.match(true, by_email(OFF, false).ok);
	});

	it('with the option off, an email matches whatever email_verified says, as before', () => {
		for (let v in [ true, false, 'true', null ])
			assert.match(contains({ ok: true, data: { role_name: 'readers' } }), by_email(OFF, v), `${v}`);
		assert.match(contains({ ok: true, data: { role_name: 'readers' } }),
			config.find_role_for_user(OFF, { email: 'alice@example.com' }));
	});

	it('a group still matches while the email is not verified', () => {
		let cfg = { roles: [ROLE_READERS, ROLE_WRITERS] };
		let res = config.find_role_for_user(cfg, { email: 'alice@example.com', email_verified: false, groups: ['developers'] });
		assert.match({ ok: true, data: { role_name: 'writers', also_matched: [] } }, res);
	});

	it('an unverified email that would match an earlier role does not skip ahead of a group match', () => {
		// readers matches alice by email only; admin matches by group. With
		// the email unverified, readers is not even listed.
		let res = config.find_role_for_user({ roles: [ROLE_READERS, ROLE_ADMIN] },
			{ email: 'alice@example.com', email_verified: 'false', groups: ['admins'] });
		assert.match({ ok: true, data: { role_name: 'admin', also_matched: [] } }, res);
	});

	prop('with the option on, an email matches iff email_verified is the boolean true',
		gen.oneof(gen.bool(), gen.elements('true', 'false', 'True', '1', ''), gen.string({ max_len: 6 }), gen.int(-2, 2)),
		(v, ctx) => {
			let verified = (v === true);
			ctx.classify('verified', verified);
			assert.match(verified, by_email(ON, v).ok);
			assert.match(true, by_email(OFF, v).ok);
		}
	);
});

describe('config: matchable_email', () => {
	it('returns the email when it is verified, or when the option is off', () => {
		assert.match('a@b.c', config.matchable_email({}, { email: 'a@b.c', email_verified: true }));
		assert.match('a@b.c', config.matchable_email({ require_email_verified: false }, { email: 'a@b.c' }));
	});

	it('returns null for an unverified, empty, missing or non-string email', () => {
		assert.match(null, config.matchable_email({}, { email: 'a@b.c', email_verified: false }));
		for (let e in [ '', null, 42, [ 'a@b.c' ] ]) {
			assert.match(null, config.matchable_email({}, { email: e, email_verified: true }), `${e}`);
			assert.match(null, config.matchable_email({ require_email_verified: false }, { email: e }), `${e}`);
		}
		assert.match(null, config.matchable_email({}, {}));
	});
});

describe('config: session_email', () => {
	it('returns a verified email, the label a session is stored with', () => {
		assert.match('a@b.c', config.session_email({ email: 'a@b.c', email_verified: true }));
	});

	it('returns null for an unverified or unflagged email, or the string "true"', () => {
		for (let v in [ false, 'true', 'false', null ])
			assert.match(null, config.session_email({ email: 'a@b.c', email_verified: v }), `${v}`);
		assert.match(null, config.session_email({ email: 'a@b.c' }));
	});

	it('returns null for an unverified email even where require_email_verified off lets it match a role', () => {
		let claims = { email: 'a@b.c', email_verified: false };
		assert.match('a@b.c', config.matchable_email({ require_email_verified: false }, claims), 'it matches');
		assert.match(null, config.session_email(claims), 'but is not a label');
	});

	it('returns null for an empty, missing or non-string email', () => {
		for (let e in [ '', null, 42, [ 'a@b.c' ] ])
			assert.match(null, config.session_email({ email: e, email_verified: true }), `${e}`);
		assert.match(null, config.session_email({}));
	});
});

// ─── load — success & normalization ────────────────────────────────────────────

describe('config: load — success', () => {
	it('loads a valid OIDC config with roles', () => {
		let res = load_sections({ default: { ...OIDC }, r1: { ...ROLE } });
		assert.match(contains({ ok: true }), res);
		assert.match('https://idp.com', res.data.issuer_url);
		assert.match(300, res.data.clock_tolerance);
		assert.match('r1', res.data.roles[0].name);
	});

	it('normalizes a single email string to an array and preserves an email list', () => {
		let res = load_sections({
			default: { ...OIDC },
			r1: { ...ROLE, email: 'single@test.com' },
			r2: { ...ROLE, email: ['a@b.com', 'c@d.com'] },
		});
		assert.match(contains({ ok: true }), res);
		assert.match('array', type(res.data.roles[0].emails));
		assert.match(2, length(res.data.roles[1].emails));
	});

	it('maps multiple roles, in config order, to their name and matching rules only', () => {
		let res = load_sections({
			default: { ...OIDC },
			r1: { ...ROLE, email: ['admin@test.com'] },
			r2: { ".type": "role", email: ['jane@test.com'], group: 'staff' },
		});
		assert.match(contains({ ok: true }), res);
		assert.match([
			{ name: 'r1', emails: ['admin@test.com'], groups: [], subs: [] },
			{ name: 'r2', emails: ['jane@test.com'], groups: ['staff'], subs: [] },
		], res.data.roles);
	});

	it('loads a sub list, normalizing a single sub string to an array, and keeps each sub as written', () => {
		let res = load_sections({
			default: { ...OIDC },
			one: { ".type": "role", sub: 'Ab-12' },
			many: { ".type": "role", sub: [ '248289761001', 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6' ], email: 'x@test.com' },
		});
		assert.match(contains({ ok: true }), res);
		assert.match([
			{ name: 'one', emails: [], groups: [], subs: [ 'Ab-12' ] },
			{ name: 'many', emails: [ 'x@test.com' ], groups: [], subs: [ '248289761001', 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6' ] },
		], res.data.roles);
	});

	it('a role with only a sub is valid', () => {
		let res = load_sections({ default: { ...OIDC }, subonly: { ".type": "role", sub: [ '248289761001' ] } });
		assert.match(contains({ ok: true }), res);
		assert.match([ 'subonly' ], map(res.data.roles, (r) => r.name));
	});

	it('ignores a role with no email, no group and no sub, with a warning', () => {
		let logs = [];
		let res = load_sections({ default: { ...OIDC }, empty: { ".type": "role" }, r1: { ...ROLE } }, logs);
		assert.match(contains({ ok: true }), res);
		assert.match([ 'r1' ], map(res.data.roles, (r) => r.name));
		assert.match([ [ 'warn', "Ignoring role 'empty': missing email, group or sub list" ] ],
			filter(logs, (l) => index(l[1], 'Ignoring role') == 0));
	});

	it('ignores read/write lists left on a role, with a warning naming its rpcd login entry', () => {
		let logs = [];
		let res = load_sections({
			default: { ...OIDC },
			old: { ...ROLE, read: ['*'], write: ['*'] },
			half: { ...ROLE, write: 'luci-base' },
			clean: { ...ROLE },
		}, logs);
		assert.match(contains({ ok: true }), res);
		assert.match([ 'old', 'half', 'clean' ], map(res.data.roles, (r) => r.name));
		for (let r in res.data.roles) {
			assert.match(false, exists(r, 'read'));
			assert.match(false, exists(r, 'write'));
		}
		let warns = filter(logs, (l) => l[0] == 'warn' && index(l[1], 'Ignoring read/write') == 0);
		assert.match([
			[ 'warn', "Ignoring read/write on role 'old': its permissions are the rpcd login entry 'luci_sso_old'" ],
			[ 'warn', "Ignoring read/write on role 'half': its permissions are the rpcd login entry 'luci_sso_half'" ],
		], warns);
	});

	it('require_email_verified is on by default and off only for a UCI false value', () => {
		assert.match(true, load_sections({ default: { ...OIDC }, r1: { ...ROLE } }).data.require_email_verified, 'unset');
		for (let v in [ '1', 'yes', 'on', 'true', '' ])
			assert.match(true, load_sections({ default: { ...OIDC, require_email_verified: v }, r1: { ...ROLE } }).data.require_email_verified, `'${v}'`);
		for (let v in [ '0', 'no', 'off', 'false' ])
			assert.match(false, load_sections({ default: { ...OIDC, require_email_verified: v }, r1: { ...ROLE } }).data.require_email_verified, `'${v}'`);
	});

	it('loads a custom scope and leaves it undefined when absent', () => {
		let with_scope = load_sections({ default: { ...OIDC, scope: 'openid email custom_scope' }, r1: { ...ROLE } });
		assert.match('openid email custom_scope', with_scope.data.scope);
		let no_scope = load_sections({ default: { ...OIDC }, r1: { ...ROLE } });
		assert.match(undefined, no_scope.data.scope);
	});
});

// ─── load — validation ─────────────────────────────────────────────────────────

describe('config: load — validation', () => {
	it('rejects a config with no valid roles', () => {
		let res = load_sections({ default: { ...OIDC } });
		assert.match(contains({ ok: false, error: 'CONFIG_ERROR' }), res);
		assert.match(true, index(res.details, 'No valid roles') != -1);
	});

	it('rejects missing mandatory OIDC fields', () => {
		for (let missing in ['issuer_url', 'clock_tolerance', 'client_id', 'client_secret']) {
			let d = { ...OIDC };
			delete d[missing];
			assert.match(contains({ ok: false, error: 'CONFIG_ERROR' }), load_sections({ default: d, r1: { ...ROLE } }), `missing ${missing}`);
		}
	});

	it('rejects insecure issuer_url and redirect_uri (http)', () => {
		assert.match(false, load_sections({ default: { ...OIDC, issuer_url: 'http://idp.com' }, r1: { ...ROLE } }).ok);
		assert.match(contains({ ok: false, error: 'CONFIG_ERROR' }), load_sections({ default: { ...OIDC, redirect_uri: 'http://insecure.com/callback' }, r1: { ...ROLE } }));
	});

	it('rejects an insecure internal_issuer_url (W3)', () => {
		let res = load_sections({ default: { ...OIDC, internal_issuer_url: 'http://10.0.0.5' }, r1: { ...ROLE } });
		assert.match(contains({ ok: false, error: 'CONFIG_ERROR' }), res);
		assert.match(true, index(res.details, 'internal_issuer_url must use HTTPS') >= 0);
	});

	it('rejects an internal_issuer_url with a path, query or fragment, without echoing it', () => {
		for (let bad in [ 'https://10.0.0.5/realms/home', 'https://10.0.0.5:8443/x/', 'https://10.0.0.5?a=1', 'https://10.0.0.5#frag' ]) {
			let res = load_sections({ default: { ...OIDC, internal_issuer_url: bad }, r1: { ...ROLE } });
			assert.match(contains({ ok: false, error: 'CONFIG_ERROR' }), res, bad);
			assert.match(true, index(res.details, 'internal_issuer_url must be an origin') == 0, bad);
			assert.match(-1, index(res.details, '10.0.0.5'), 'the value is never part of the reason');
		}
	});

	it('accepts an internal_issuer_url that is an origin, with or without a port or trailing slash', () => {
		for (let good in [ 'https://10.0.0.5', 'https://10.0.0.5:8443', 'https://idp.lan/', 'https://[fd00::5]:8443/' ])
			assert.match(true, load_sections({ default: { ...OIDC, internal_issuer_url: good }, r1: { ...ROLE } }).ok, good);
	});

	it('accepts case-insensitive HTTPS schemes (RFC 3986)', () => {
		assert.match(true, load_sections({ default: { ...OIDC, issuer_url: 'HTTPS://idp.com' }, r1: { ...ROLE } }).ok);
		assert.match(true, load_sections({ default: { ...OIDC, redirect_uri: 'HTTPS://app.com/callback' }, r1: { ...ROLE } }).ok);
		assert.match(true, load_sections({ default: { ...OIDC, internal_issuer_url: 'HTTPS://internal.com' }, r1: { ...ROLE } }).ok);
		assert.match(true, load_sections({ default: { ...OIDC, issuer_url: 'hTTpS://idp.com' }, r1: { ...ROLE } }).ok);
	});

	it('enforces clock_tolerance in [0, 3600] (N4/N5)', () => {
		for (let ok_val in ['0', '3600', '60'])
			assert.match(true, load_sections({ default: { ...OIDC, clock_tolerance: ok_val }, r1: { ...ROLE } }).ok, `tolerance ${ok_val}`);

		let neg = load_sections({ default: { ...OIDC, clock_tolerance: '-1' }, r1: { ...ROLE } });
		assert.match(contains({ ok: false, error: 'CONFIG_ERROR' }), neg);
		assert.match(true, index(neg.details, 'between 0 and 3600') != -1);

		for (let bad in ['3601', 'abc'])
			assert.match(contains({ ok: false, error: 'CONFIG_ERROR' }), load_sections({ default: { ...OIDC, clock_tolerance: bad }, r1: { ...ROLE } }), `tolerance ${bad}`);
	});
});

// ─── enabled state ─────────────────────────────────────────────────────────────

describe('config: enabled state', () => {
	it('load returns SSO_DISABLED when disabled or missing', () => {
		assert.match(contains({ ok: false, error: 'SSO_DISABLED' }), load_sections({ default: { ".type": "oidc", enabled: "0" } }));
		assert.match(contains({ ok: false, error: 'SSO_DISABLED' }), load_sections({}));
	});

	it('is_enabled reflects the UCI enabled flag', () => {
		let e = is_enabled_sections({ default: { ".type": "oidc", enabled: "1" } });
		assert.match(true, e.ok && e.data);
		let d = is_enabled_sections({ default: { ".type": "oidc", enabled: "0" } });
		assert.match(false, d.ok && d.data);
		let m = is_enabled_sections({});
		assert.match(false, m.ok && m.data);
	});
});
