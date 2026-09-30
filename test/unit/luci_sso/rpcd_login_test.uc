import { describe, it, prop, gen, assert, contains, mock } from 'utest';
import * as rpcd_login from 'luci_sso.rpcd_login';

describe('rpcd_login: section_name and username', () => {
	it('name the entry luci_sso_<role> with username sso:<role>', () => {
		assert.match("luci_sso_viewer", rpcd_login.section_name("viewer"));
		assert.match("sso:viewer", rpcd_login.username("viewer"));
	});
});

describe('rpcd_login: role_of — what makes a session an SSO session', () => {
	it('returns the role of an sso:<role> username', () => {
		assert.match("viewer", rpcd_login.role_of("sso:viewer"));
		assert.match("viewer", rpcd_login.role_of(rpcd_login.username("viewer")));
	});

	it('returns null for any other username', () => {
		for (let name in [ "root", "admin", "sso:", "sso:bad-name", "sso:a b", "SSO:viewer", " sso:viewer", null, 1, {} ])
			assert.match(null, rpcd_login.role_of(name), `${name}`);
	});

	it('returns null for a role name longer than NAME_MAX', () => {
		let long = "";
		for (let i = 0; i <= rpcd_login.NAME_MAX; i++) long += "a";
		assert.match(null, rpcd_login.role_of("sso:" + long));
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

describe('rpcd_login: check_name', () => {
	it('accepts letters, digits and underscores, up to 32 characters', () => {
		assert.match(contains({ ok: true, data: "Viewer_2" }), rpcd_login.check_name("Viewer_2"));
		assert.match(contains({ ok: true }), rpcd_login.check_name(sprintf("%032d", 0)));
	});

	it('refuses a missing, empty, too long or badly formed name with INVALID_NAME', () => {
		for (let bad in [ null, 42, "", sprintf("%033d", 0), "a-b", "a b", "../root", "sso:x", "x\n" ])
			assert.match(contains({ ok: false, error: "INVALID_NAME" }), rpcd_login.check_name(bad), `${bad}`);
	});
});

describe('rpcd_login: check_list', () => {
	it('accepts an array of access groups and patterns, empty included', () => {
		assert.match(contains({ ok: true }), rpcd_login.check_list("read", []));
		assert.match(contains({ ok: true }), rpcd_login.check_list("read", [ "*", "luci-?ase", "!luci-mod-*" ]));
	});

	it('refuses anything else with INVALID_LIST, naming the entry', () => {
		assert.match(contains({ ok: false, error: "INVALID_LIST", details: "read must be an array of strings" }), rpcd_login.check_list("read", "*"));
		assert.match(contains({ ok: false, error: "INVALID_LIST", details: "write[1] is not a string" }), rpcd_login.check_list("write", [ "a", 1 ]));
		assert.match(contains({ ok: false, error: "INVALID_LIST", details: "read[0] is empty" }), rpcd_login.check_list("read", [ "" ]));
		assert.match(contains({ ok: false, error: "INVALID_LIST", details: "read[0] contains a control character" }), rpcd_login.check_list("read", [ "a\nlist write *" ]));
		assert.match(contains({ ok: false, error: "INVALID_LIST" }), rpcd_login.check_list("read", [ "a" + chr(0) ]));
		assert.match(contains({ ok: false, error: "INVALID_LIST" }), rpcd_login.check_list("read", [ sprintf("%0129d", 0) ]));
		let many = [];
		for (let i = 0; i < 129; i++) push(many, `g${i}`);
		assert.match(contains({ ok: false, error: "INVALID_LIST" }), rpcd_login.check_list("read", many));
	});
});

describe('rpcd_login: with_baseline — the unauthenticated group', () => {
	it('appends the group to a list that does not grant it', () => {
		assert.match(contains({ ok: true, data: [ "unauthenticated" ] }), rpcd_login.with_baseline([]));
		assert.match(contains({ ok: true, data: [ "luci-base", "luci-mod-status-*", "unauthenticated" ] }),
			rpcd_login.with_baseline([ "luci-base", "luci-mod-status-*" ]));
	});

	it('keeps a list that grants it already, by name or through a pattern, as it is', () => {
		for (let read in [ [ "unauthenticated" ], [ "luci-base", "unauthenticated" ], [ "*" ], [ "unauth*" ], [ "*", "!luci-mod-*" ] ])
			assert.match(contains({ ok: true, data: read }), rpcd_login.with_baseline(read), `${read}`);
	});

	it('refuses a list whose negation denies the group, since appending it could not undo that', () => {
		for (let read in [ [ "!unauthenticated" ], [ "*", "!unauth*" ], [ "unauthenticated", "!*" ] ])
			assert.match(contains({ ok: false, error: "INVALID_LIST" }), rpcd_login.with_baseline(read), `${read}`);
	});

	prop('the stored list grants read on the group, and storing it again changes nothing',
		gen.array(gen.elements("*", "luci-base", "luci-*", "unauthenticated", "unauth?nticated", "!luci-base", "other", "u*"), { min_len: 0, max_len: 5 }),
		(read, ctx) => {
			let once = rpcd_login.with_baseline(read);
			ctx.classify('appended', length(once.data) > length(read));
			assert.match(true, once.ok);
			assert.match(true, rpcd_login.permits({ read: once.data, write: [] }, "read", "unauthenticated"));
			let appended = length(once.data) - length(read);
			assert.match(appended ? [ ...read, "unauthenticated" ] : read, once.data, "the list, plus the name at most once");
			if (appended) assert.match(-1, index(read, "unauthenticated"), "never a second copy of the name");
			assert.match(once, rpcd_login.with_baseline(once.data));
		}
	);
});

describe('rpcd_login: entry', () => {
	it('returns the entry to store: section, username and the lists, read with the group', () => {
		assert.match({ ok: true, data: { name: "viewer", section: "luci_sso_viewer", username: "sso:viewer",
			read: [ "luci-base", "unauthenticated" ], write: [] } },
			rpcd_login.entry("viewer", [ "luci-base" ], []));
	});

	it('accepts a role that grants nothing else: its read list is the group alone', () => {
		assert.match(contains({ ok: true, data: contains({ read: [ "unauthenticated" ], write: [] }) }), rpcd_login.entry("nobody", [], []));
	});

	it('refuses a bad name or list with the check that failed', () => {
		assert.match(contains({ ok: false, error: "INVALID_NAME" }), rpcd_login.entry("a-b", [], []));
		assert.match(contains({ ok: false, error: "INVALID_LIST", details: "read must be an array of strings" }), rpcd_login.entry("a", null, []));
		assert.match(contains({ ok: false, error: "INVALID_LIST", details: "write must be an array of strings" }), rpcd_login.entry("a", [], "*"));
		assert.match(contains({ ok: false, error: "INVALID_LIST" }), rpcd_login.entry("a", [ "!unauthenticated" ], []));
	});
});

describe('rpcd_login: stage', () => {
	// The UCI calls stage() makes on a cursor over the given rpcd sections.
	let staged = (sections, e) => {
		let calls = null;
		mock.inject('uci', { strict: true, data: { rpcd: sections } }, (uci) => {
			let cur = uci.cursor();
			rpcd_login.stage(cur, e);
			calls = cur.__utest__.calls;
		});
		return calls;
	};
	let E = { name: "v", section: "luci_sso_v", username: "sso:v", read: [ "luci-base", "unauthenticated" ], write: [] };

	it('creates the login, sets the username and the lists, and removes a password and an empty list', () => {
		let calls = staged({}, E);
		assert.match([
			[ "rpcd", "luci_sso_v", null, "login" ],
			[ "rpcd", "luci_sso_v", "username", "sso:v" ],
			[ "rpcd", "luci_sso_v", "read", [ "luci-base", "unauthenticated" ] ],
		], map(calls.set, (c) => (c[3] == null) ? [ c[0], c[1], null, c[2] ] : c));
		assert.match([
			[ "rpcd", "luci_sso_v", "password" ],
			[ "rpcd", "luci_sso_v", "read" ],
			[ "rpcd", "luci_sso_v", "write" ],
		], calls["delete"]);
		assert.match([], calls.commit, "the caller commits");
	});

	it('keeps an existing login section instead of recreating it', () => {
		let calls = staged({ luci_sso_v: { ".type": "login", username: "sso:v", password: "x" } }, E);
		assert.match(0, length(filter(calls.set, (c) => c[2] == "login")));
		assert.match(true, length(filter(calls["delete"], (c) => c[2] == "password")) == 1);
	});
});

describe('rpcd_login: is_placeholder — the shipped admin role', () => {
	it('is the admin role matching admin@example.com and nothing else', () => {
		assert.match(true, rpcd_login.is_placeholder({ ".name": "admin", email: [ "admin@example.com" ] }));
		assert.match(true, rpcd_login.is_placeholder({ ".name": "admin", email: "admin@example.com" }), "a single option");
		assert.match(true, rpcd_login.is_placeholder({ ".name": "admin", email: [ "admin@example.com" ], group: [] }));
	});

	it('is not a role that says who its users are', () => {
		for (let s in [
			{ ".name": "ops", email: [ "admin@example.com" ] },
			{ ".name": "admin", email: [ "alice@corp.example" ] },
			{ ".name": "admin", email: [ "admin@example.com", "alice@corp.example" ] },
			{ ".name": "admin", email: [ "admin@example.com" ], group: [ "admins" ] },
			{ ".name": "admin", email: [ "admin@example.com" ], group: "admins" },
			{ ".name": "admin", email: [ "Admin@example.com" ] },
			{ ".name": "admin", group: [ "admins" ] },
			{ ".name": "admin", email: [ "admin@example.com" ], sub: [ "248289761001" ] },
			{ ".name": "admin", email: [ "admin@example.com" ], sub: "248289761001" },
			{ ".name": "admin", sub: [ "248289761001" ] },
			{ ".name": "admin" },
		])
			assert.match(false, rpcd_login.is_placeholder(s), sprintf("%J", s));
	});
});
