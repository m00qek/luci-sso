import { describe, it, prop, gen, assert, contains, pred } from 'utest';
import * as config from 'luci_sso.config';

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
