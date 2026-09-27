import { describe, it, assert, contains } from 'utest';
import * as fs from 'fs';
import * as uci from 'uci';
import * as rpcd_login from 'luci_sso.rpcd_login';

// System bucket: the upgrade from releases that kept read/write lists on the
// luci-sso role (rpcd_login.migrate, run by files/etc/uci-defaults/20-luci-sso-rpcd).
// It runs on REAL UCI files, in a scratch configuration directory, so the
// container's own /etc/config is never touched.

const DIR = "/tmp/luci-sso-migration-test";

const OLD_LUCI_SSO = `
config oidc 'default'
	option enabled '1'
	option issuer_url 'https://idp.example.com'

config role 'admin'
	list email 'admin@example.com'
	list read '*'
	list write '*'

config role 'viewer'
	list group 'viewers'
	list read 'luci-base'
	list read 'luci-mod-status-*'

config role 'single'
	list email 'single@example.com'
	option read '*'
	list write 'luci-mod-system-config'

config role 'nolists'
	list email 'nolists@example.com'

config role 'this_role_name_is_longer_than_32_chars'
	list email 'long@example.com'
	list read '*'

config role 'denies'
	list email 'denies@example.com'
	list read '*'
	list read '!unauthenticated'
`;

const RPCD = `
config rpcd
	option socket '/var/run/ubus/ubus.sock'
	option timeout '30'

config login
	option username 'root'
	option password '$p$root'
	list read '*'
	list write '*'

config login 'luci_sso_viewer'
	option username 'someone'
	option password '$p$root'
	list read 'stale'

config login 'guest'
	option username 'guest'
	option password '$p$guest'
	list read 'luci-base'
`;

function setup(luci_sso, rpcd) {
	system(`rm -rf ${DIR}; mkdir -p ${DIR}/delta`);
	fs.writefile(`${DIR}/luci-sso`, luci_sso);
	fs.writefile(`${DIR}/rpcd`, rpcd);
}

// Runs the migration as the uci-defaults script does: stage, then commit what
// changed, rpcd first. Returns { changed, warnings }.
function run() {
	let cur = uci.cursor(DIR, `${DIR}/delta`);
	let warnings = [];
	let changed = rpcd_login.migrate(cur, (m) => push(warnings, m));
	if (changed.rpcd) cur.commit("rpcd");
	if (changed.luci_sso) cur.commit("luci-sso");
	return { changed, warnings };
}

function files() {
	return { luci_sso: fs.readfile(`${DIR}/luci-sso`), rpcd: fs.readfile(`${DIR}/rpcd`) };
}

function sections(config) {
	let out = [];
	uci.cursor(DIR, `${DIR}/delta`).foreach(config, null, (s) => push(out, s));
	return out;
}

function section(config, name) {
	return uci.cursor(DIR, `${DIR}/delta`).get_all(config, name);
}

function with_dir(fn) {
	let failure = null;
	try { fn(); } catch (e) { failure = e; }
	system(`rm -rf ${DIR}`);
	if (failure != null) die(failure);
}

describe('system: rpcd_login.migrate — an old-style configuration', () => {
	it("moves each role's lists into its rpcd entry, by set_role's rules", () => {
		with_dir(() => {
			setup(OLD_LUCI_SSO, RPCD);
			let res = run();
			assert.match({ rpcd: true, luci_sso: true }, res.changed);

			assert.match(contains({ ".type": "login", username: "sso:admin", read: [ "*" ], write: [ "*" ] }), section("rpcd", "luci_sso_admin"),
				"'*' is rpcd's '*', and grants unauthenticated already");
			let viewer = section("rpcd", "luci_sso_viewer");
			assert.match(contains({ ".type": "login", username: "sso:viewer", read: [ "luci-base", "luci-mod-status-*", "unauthenticated" ] }), viewer,
				"an existing entry is replaced: username repaired, lists from the role, unauthenticated added");
			assert.match(false, exists(viewer, "password"), "and its password removed");
			assert.match(false, exists(viewer, "write"));
			assert.match(contains({ read: [ "*" ], write: [ "luci-mod-system-config" ] }), section("rpcd", "luci_sso_single"),
				"a single read option is read as a one-entry list, as luci-sso used to");
		});
	});

	it('removes the lists from the migrated roles and keeps the roles, their rules and their order', () => {
		with_dir(() => {
			setup(OLD_LUCI_SSO, RPCD);
			run();
			let roles = filter(sections("luci-sso"), (s) => s[".type"] == "role");
			assert.match([ "admin", "viewer", "single", "nolists", "this_role_name_is_longer_than_32_chars", "denies" ],
				map(roles, (s) => s[".name"]), "same roles, same order");
			for (let s in roles) {
				if (index([ "admin", "viewer", "single" ], s[".name"]) >= 0) {
					assert.match(false, exists(s, "read") || exists(s, "write"), `${s[".name"]} has no lists left`);
				}
			}
			assert.match(contains({ group: [ "viewers" ] }), section("luci-sso", "viewer"), "matching rules stay");
			assert.match(contains({ enabled: "1", issuer_url: "https://idp.example.com" }), section("luci-sso", "default"));
		});
	});

	it("leaves a role the rules refuse as it was, with a warning naming it", () => {
		with_dir(() => {
			setup(OLD_LUCI_SSO, RPCD);
			let res = run();
			assert.match(3, length(res.warnings));
			assert.match(true, index(res.warnings[1], "role 'this_role_name_is_longer_than_32_chars' keeps its read/write lists") == 0, res.warnings[1]);
			assert.match(true, index(res.warnings[2], "role 'denies' keeps its read/write lists") == 0, res.warnings[2]);
			assert.match(contains({ read: [ "*" ] }), section("luci-sso", "this_role_name_is_longer_than_32_chars"));
			assert.match(contains({ read: [ "*", "!unauthenticated" ] }), section("luci-sso", "denies"));
			assert.match(null, section("rpcd", "luci_sso_denies"));
		});
	});

	it("gives a role without lists an entry that grants nothing, with a warning naming it", () => {
		with_dir(() => {
			setup(OLD_LUCI_SSO, RPCD);
			let res = run();
			let e = section("rpcd", "luci_sso_nolists");
			assert.match(contains({ ".type": "login", username: "sso:nolists", read: [ "unauthenticated" ] }), e);
			assert.match(false, exists(e, "write") || exists(e, "password"));
			assert.match("role 'nolists' had no permissions to move: its rpcd login entry grants nothing but 'unauthenticated'; set its permissions on the settings page",
				res.warnings[0]);
		});
	});

	it("never touches an rpcd section that is not luci_sso_*, and never writes a password", () => {
		with_dir(() => {
			setup(OLD_LUCI_SSO, RPCD);
			let others = (list) => filter(list, (s) => index(s[".name"], "luci_sso_") != 0);
			let before = others(sections("rpcd"));
			run();
			assert.match(before, others(sections("rpcd")));
			for (let s in sections("rpcd"))
				if (index(s[".name"], "luci_sso_") == 0) assert.match(false, exists(s, "password"), s[".name"]);
		});
	});

	it('a second run changes nothing: no commit, same files, and only the refused roles warn again', () => {
		with_dir(() => {
			setup(OLD_LUCI_SSO, RPCD);
			run();
			let after_first = files();
			let res = run();
			assert.match({ rpcd: false, luci_sso: false }, res.changed);
			assert.match(after_first, files());
			assert.match(2, length(res.warnings));
		});
	});

	it('an upgrade interrupted after the rpcd commit is completed by the next run', () => {
		with_dir(() => {
			setup(OLD_LUCI_SSO, RPCD);
			let cur = uci.cursor(DIR, `${DIR}/delta`);
			rpcd_login.migrate(cur, () => null);
			cur.commit("rpcd");
			cur.revert("luci-sso");
			assert.match(contains({ read: [ "luci-base", "luci-mod-status-*" ] }), section("luci-sso", "viewer"), "lists still there");

			assert.match({ rpcd: true, luci_sso: true }, run().changed);
			assert.match(false, exists(section("luci-sso", "viewer"), "read"));
			let after = files();
			run();
			assert.match(after, files());
		});
	});
});

describe('system: rpcd_login.migrate — the shipped admin role', () => {
	const FRESH = "config oidc 'default'\n\toption enabled '0'\n\nconfig role 'admin'\n\tlist email 'admin@example.com'\n";

	// FRESH's admin role is the one files/etc/config/luci-sso ships.
	it('is_placeholder matches the role the package ships', () => {
		with_dir(() => {
			setup(FRESH, RPCD);
			assert.match(true, rpcd_login.is_placeholder(section("luci-sso", "admin")));
		});
		assert.match(false, rpcd_login.is_placeholder({ ".name": "ops", email: [ "admin@example.com" ] }), "another name");
		assert.match(true, rpcd_login.is_placeholder({ ".name": "admin", email: "admin@example.com" }), "a single option too");
	});

	it('a fresh install gives the admin role read and write on everything', () => {
		with_dir(() => {
			setup(FRESH, RPCD);
			let res = run();
			assert.match({ rpcd: true, luci_sso: false }, res.changed);
			assert.match([], res.warnings);
			assert.match(contains({ username: "sso:admin", read: [ "*" ], write: [ "*" ] }), section("rpcd", "luci_sso_admin"));
			let after = files();
			assert.match({ rpcd: false, luci_sso: false }, run().changed, "then nothing more");
			assert.match(after, files());
		});
	});

	// An old config whose admin role names real users but has no lists: its
	// users were refused before, and must not become full administrators.
	const EDITED = {
		"real emails":            "\tlist email 'alice@corp.example'\n\tlist email 'bob@corp.example'\n",
		"a group":                "\tlist group 'admins'\n",
		"the placeholder and a group": "\tlist email 'admin@example.com'\n\tlist group 'admins'\n",
		"the placeholder and another email": "\tlist email 'admin@example.com'\n\tlist email 'alice@corp.example'\n",
		"another case":           "\tlist email 'Admin@Example.com'\n",
		"no rule at all":         "",
	};
	for (let what, rules in EDITED) {
		it(`an admin role with ${what} and no lists gets an entry that grants nothing, and a warning`, () => {
			with_dir(() => {
				setup(`config role 'admin'\n${rules}`, RPCD);
				let res = run();
				assert.match({ rpcd: true, luci_sso: false }, res.changed);
				let e = section("rpcd", "luci_sso_admin");
				assert.match(contains({ username: "sso:admin", read: [ "unauthenticated" ] }), e);
				assert.match(false, exists(e, "write") || exists(e, "password"));
				assert.match([ "role 'admin' had no permissions to move: its rpcd login entry grants nothing but 'unauthenticated'; set its permissions on the settings page" ],
					res.warnings);
				let after = files();
				res = run();
				assert.match({ changed: { rpcd: false, luci_sso: false }, warnings: [] }, res, "then nothing more");
				assert.match(after, files());
			});
		});
	}

	it("an admin entry that exists is kept as it is, however restricted", () => {
		with_dir(() => {
			setup(FRESH, `${RPCD}\nconfig login 'luci_sso_admin'\n\toption username 'sso:admin'\n\tlist read 'unauthenticated'\n`);
			let before = files();
			assert.match({ changed: { rpcd: false, luci_sso: false }, warnings: [] }, run());
			assert.match(before, files());
		});
	});

	it('no admin role, no admin entry; another role without lists gets one that grants nothing', () => {
		with_dir(() => {
			setup("config role 'ops'\n\tlist email 'ops@example.com'\n", RPCD);
			let res = run();
			assert.match({ rpcd: true, luci_sso: false }, res.changed);
			assert.match(null, section("rpcd", "luci_sso_admin"));
			assert.match(contains({ username: "sso:ops", read: [ "unauthenticated" ] }), section("rpcd", "luci_sso_ops"));
			assert.match(1, length(res.warnings));
		});
	});
});
