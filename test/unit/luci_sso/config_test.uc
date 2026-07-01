import { describe, it, prop, gen, assert, contains, pred, mock } from 'utest';
import * as config from 'luci_sso.config';

// config.load / config.is_enabled read UCI via the injected `uci` proxy.
const OIDC = {
	".type": "oidc", enabled: "1",
	issuer_url: "https://idp.com", client_id: "c1", client_secret: "s1",
	redirect_uri: "https://r1/callback", clock_tolerance: "300",
};
const ROLE = { ".type": "role", email: "admin@test.com", read: ["*"], write: ["*"] };

function load_sections(sections) {
	let res;
	mock.inject('uci', { data: { "luci-sso": sections } }, (uci) => {
		res = config.load({ uci: uci.cursor(), log: () => null });
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

function has_no_duplicates(arr) {
	for (let i = 1; i < length(arr); i++)
		for (let j = 0; j < i; j++)
			if (arr[j] == arr[i]) return false;
	return true;
}

const ROLE_READERS = {
	name: 'readers',
	emails: ['alice@example.com'],
	groups: [],
	read: ['luci-app-firewall'],
	write: []
};

const ROLE_WRITERS = {
	name: 'writers',
	emails: [],
	groups: ['developers'],
	read: ['luci-app-firewall', 'luci-app-openvpn'],
	write: ['luci-app-openvpn']
};

const ROLE_ADMIN = {
	name: 'admin',
	emails: ['admin@example.com'],
	groups: ['admins'],
	read: ['*'],
	write: ['*']
};

// ─── find_roles_for_user ─────────────────────────────────────────────────────

describe('config: find_roles_for_user', () => {
	it('returns NO_ROLES_MATCHED when no roles are configured', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_roles_for_user({ roles: [] }, { email: 'alice@example.com' }));
	});

	it('returns NO_ROLES_MATCHED when email does not match any role', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_roles_for_user({ roles: [ROLE_ADMIN] }, { email: 'stranger@example.com' }));
	});

	it('returns NO_ROLES_MATCHED when group does not match any role', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_roles_for_user({ roles: [ROLE_ADMIN] }, { groups: ['nobody'] }));
	});

	it('returns NO_ROLES_MATCHED when matched role has no permissions', () => {
		let empty_role = { name: 'empty', emails: ['alice@example.com'], groups: [], read: [], write: [] };
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_roles_for_user({ roles: [empty_role] }, { email: 'alice@example.com' }));
	});

	it('matches by email and returns read permissions', () => {
		let res = config.find_roles_for_user({ roles: [ROLE_READERS] }, { email: 'alice@example.com' });
		assert.match(contains({ ok: true, data: { read: ['luci-app-firewall'], write: [], role_name: 'readers' } }), res);
	});

	it('email matching is case-insensitive', () => {
		let res = config.find_roles_for_user({ roles: [ROLE_READERS] }, { email: 'ALICE@EXAMPLE.COM' });
		assert.match(contains({ ok: true, data: { role_name: 'readers' } }), res);
	});

	it('matches by group and returns permissions', () => {
		let res = config.find_roles_for_user({ roles: [ROLE_WRITERS] }, { groups: ['developers'] });
		assert.match(contains({ ok: true, data: { write: ['luci-app-openvpn'], role_name: 'writers' } }), res);
	});

	it('treats non-array claims.groups as empty', () => {
		assert.match(contains({ ok: false, error: 'NO_ROLES_MATCHED' }),
			config.find_roles_for_user({ roles: [ROLE_WRITERS] }, { groups: 'developers' }));
	});

	it('merges permissions from multiple matching roles with deduplication', () => {
		let cfg = { roles: [ROLE_READERS, ROLE_WRITERS] };
		let res = config.find_roles_for_user(cfg, { email: 'alice@example.com', groups: ['developers'] });
		assert.match(contains({ ok: true }), res);
		// luci-app-firewall appears in both roles — must not be duplicated
		let read_count = 0;
		for (let r in res.data.read) if (r == 'luci-app-firewall') read_count++;
		assert.match(1, read_count);
		assert.match(true, 'luci-app-openvpn' in res.data.read);
		assert.match(contains(['luci-app-openvpn']), res.data.write);
	});

	it('role_name is the first matched role', () => {
		let cfg = { roles: [ROLE_READERS, ROLE_WRITERS] };
		let res = config.find_roles_for_user(cfg, { email: 'alice@example.com', groups: ['developers'] });
		assert.match(contains({ ok: true, data: { role_name: 'readers' } }), res);
	});

	it('matches admin by group when no email is provided', () => {
		let res = config.find_roles_for_user({ roles: [ROLE_ADMIN] }, { groups: ['admins'] });
		assert.match(contains({ ok: true, data: { role_name: 'admin' } }), res);
	});

	it('email match succeeds even when the claims group does not match the role', () => {
		let res = config.find_roles_for_user({ roles: [ROLE_ADMIN] }, { email: 'admin@example.com', groups: ['not-admins'] });
		assert.match(contains({ ok: true, data: { role_name: 'admin' } }), res);
	});

	it('group match succeeds even when the claims email does not match the role', () => {
		let res = config.find_roles_for_user({ roles: [ROLE_ADMIN] }, { email: 'other@example.com', groups: ['admins'] });
		assert.match(contains({ ok: true, data: { role_name: 'admin' } }), res);
	});

	it('allows user when one matched role is empty and another grants permissions', () => {
		let empty_role = { name: 'empty', emails: ['user@example.com'], groups: [], read: [], write: [] };
		let perm_role  = { name: 'perm',  emails: ['user@example.com'], groups: [], read: ['luci-app-firewall'], write: [] };
		let res = config.find_roles_for_user({ roles: [empty_role, perm_role] }, { email: 'user@example.com' });
		assert.match(contains({ ok: true, data: { read: ['luci-app-firewall'], role_name: 'empty' } }), res);
	});

	// When multiple matching roles grant overlapping permissions, the merged
	// result must never contain duplicate entries — doubling a permission would be
	// harmless functionally but indicates a deduplication defect.
	prop('merged permissions never contain duplicates',
		gen.array(gen.alphanumeric({ min_len: 1, max_len: 20 }), { min_len: 1, max_len: 6 }),
		(read_perms) => {
			// Two roles with identical permissions both match alice by email.
			let role  = { name: 'r1', emails: ['alice@example.com'], groups: [], read: read_perms, write: read_perms };
			let role2 = { ...role, name: 'r2' };
			let res = config.find_roles_for_user({ roles: [role, role2] }, { email: 'alice@example.com' });
			assert.match(contains({ ok: true, data: { read: pred(has_no_duplicates), write: pred(has_no_duplicates) } }), res);
		}
	);
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

	it('maps multiple roles with their emails and permissions', () => {
		let res = load_sections({
			default: { ...OIDC },
			r1: { ...ROLE, email: ['admin@test.com'] },
			r2: { ".type": "role", email: ['jane@test.com'], read: ['luci-mod-network'], write: [] },
		});
		assert.match(contains({ ok: true }), res);
		assert.match(2, length(res.data.roles));
		assert.match('jane@test.com', res.data.roles[1].emails[0]);
		assert.match('luci-mod-network', res.data.roles[1].read[0]);
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
