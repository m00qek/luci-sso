import { describe, it, assert } from 'utest';
import * as rpcd_login from 'luci_sso.rpcd_login';

describe('rpcd_login: section_name and username', () => {
	it('name the entry luci_sso_<role> with username sso:<role>', () => {
		assert.match("luci_sso_viewer", rpcd_login.section_name("viewer"));
		assert.match("sso:viewer", rpcd_login.username("viewer"));
	});
});

describe('rpcd_login: permits — rpcd rules', () => {
	let can = (lists, perm, group) => rpcd_login.permits(lists, perm, group);

	it('a group named in the list is permitted, another is not', () => {
		assert.match(true, can({ read: [ "luci-base" ], write: [] }, "read", "luci-base"));
		assert.match(false, can({ read: [ "luci-base" ], write: [] }, "read", "luci-app-x"));
		assert.match(false, can({ read: [ "luci-base" ], write: [] }, "write", "luci-base"));
	});

	it("patterns follow fnmatch: '*' matches every group, LuCI's or not", () => {
		assert.match(true, can({ read: [ "*" ] }, "read", "unauthenticated"));
		assert.match(true, can({ read: [ "luci-?ase" ] }, "read", "luci-base"));
		assert.match(true, can({ read: [ "luci-[a-m]*" ] }, "read", "luci-base"));
		assert.match(false, can({ read: [ "luci-[!a-m]*" ] }, "read", "luci-base"));
		assert.match(false, can({ read: [ "luci-*" ] }, "read", "unauthenticated"));
	});

	it('write implies read', () => {
		assert.match(true, can({ read: [], write: [ "luci-base" ] }, "read", "luci-base"));
		assert.match(false, can({ read: [ "luci-base" ], write: [] }, "write", "luci-base"));
	});

	it('a negation denies before any positive entry, whitespace after the ! skipped', () => {
		assert.match(false, can({ read: [ "*", "!luci-base" ] }, "read", "luci-base"));
		assert.match(false, can({ read: [ "*", "!  luci-base" ] }, "read", "luci-base"));
		assert.match(true, can({ read: [ "*", "!luci-base " ] }, "read", "luci-base"), "trailing whitespace is part of the pattern");
		assert.match(true, can({ read: [ "*", "!" ] }, "read", "luci-base"), "an empty negation is ignored");
	});

	it('a negation in the read list denies read even when the write list grants the group', () => {
		assert.match(false, can({ read: [ "!luci-base" ], write: [ "luci-base" ] }, "read", "luci-base"));
		assert.match(true, can({ read: [ "!luci-base" ], write: [ "luci-base" ] }, "write", "luci-base"));
		assert.match(false, can({ read: [], write: [ "*", "!luci-base" ] }, "read", "luci-base"), "a write negation also denies the read fallback");
	});

	it('only lists count: rpcd ignores a single option', () => {
		assert.match(false, can({ read: "*", write: "*" }, "read", "luci-base"));
		assert.match(false, can({ read: "*", write: "*" }, "write", "luci-base"));
		assert.match(false, can({}, "read", "luci-base"));
	});
});
