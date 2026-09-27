import { describe, it, assert, contains, regex } from 'utest';
import * as r from 'lib.rpcd';

// System bucket: the luci-sso ubus object (files/usr/share/rpcd/ucode/luci-sso.uc)
// running inside the container's REAL rpcd. The plugin is the only way the
// settings page may change /etc/config/rpcd, so these tests pin down that it
// writes only luci_sso_* login entries, always with username sso:<role> and
// never a password, and that rpcd reloads afterwards.
//
// Every role created here is named systest_*; the devenv's own entries (such
// as luci_sso_admin) are left alone and serve as "other sections".

const P = "systest_";

function call(conn, method, args) {
	let res = conn.call("luci-sso", method, args || {});
	return (res == null) ? { ubus_error: conn.error() } : res;
}

// A write that succeeds makes rpcd reload: wait for it before the next call.
function write(conn, method, args) {
	return r.await_reload(conn, (c) => call(c, method, args));
}

function cleanup() {
	for (let s in r.rpcd_sections())
		if (index(s[".name"], r.ENTRY_PREFIX + P) == 0 || index(s[".name"], "systest") == 0)
			r.drop_section(s[".name"]);
}

// Runs fn(conn) with no systest entries before or after.
function with_rpcd(fn) {
	let conn = r.connect(), failure = null;
	cleanup();
	try { fn(conn); } catch (e) { failure = e; }
	try { cleanup(); } catch (e) { if (failure == null) failure = e; }
	if (failure != null) die(failure);
}

// The sections a call must not touch: everything but the systest entries.
function others() {
	return filter(r.rpcd_sections(), (s) => index(s[".name"], r.ENTRY_PREFIX + P) != 0);
}

function entry(name) {
	return r.rpcd_cursor().get_all("rpcd", r.ENTRY_PREFIX + name);
}

function numbered(n) {
	let out = [];
	for (let i = 0; i < n; i++) push(out, `g${i}`);
	return out;
}

function sso_names(conn) {
	return filter(map(call(conn, "list_roles").roles, (x) => x.name), (n) => index(n, P) == 0);
}

describe('system: luci-sso ubus object — set_role', () => {
	it('creates a login entry named luci_sso_<role> with username sso:<role>, the lists and no password', () => {
		with_rpcd((conn) => {
			let before = others();
			let res = write(conn, "set_role", { name: `${P}viewer`, read: [ "luci-mod-status-*", "!luci-mod-status-logs" ], write: [ "luci-base" ] });
			let stored = [ "luci-mod-status-*", "!luci-mod-status-logs", "unauthenticated" ];
			assert.match({ role: { name: `${P}viewer`, read: stored, write: [ "luci-base" ] } }, res, "the reply shows the lists as stored");

			let e = entry(`${P}viewer`);
			assert.match(contains({ ".type": "login", username: `sso:${P}viewer`, read: stored, write: [ "luci-base" ] }), e);
			assert.match(false, exists(e, "password"), "an sso: entry never has a password option");
			assert.match(before, others(), "no other section changes");
		});
	});

	it('updates an entry in place: same position, new lists, and an empty list removes the option', () => {
		with_rpcd((conn) => {
			write(conn, "set_role", { name: `${P}a`, read: [ "luci-base" ], write: [ "luci-base" ] });
			write(conn, "set_role", { name: `${P}b`, read: [ "*" ], write: [] });
			write(conn, "set_role", { name: `${P}a`, read: [ "*" ], write: [] });

			assert.match([ `${P}a`, `${P}b` ], sso_names(conn));
			let e = entry(`${P}a`);
			assert.match([ "*" ], e.read, "'*' grants unauthenticated already");
			assert.match(false, exists(e, "write"));
		});
	});

	it('removes a password option an existing luci_sso_* entry has, and repairs its username', () => {
		with_rpcd((conn) => {
			r.put_login(`${r.ENTRY_PREFIX}${P}pw`, { username: "someone", password: "$p$root", read: [ "*" ] });
			write(conn, "set_role", { name: `${P}pw`, read: [ "luci-base" ], write: [] });

			let e = entry(`${P}pw`);
			assert.match(false, exists(e, "password"));
			assert.match(`sso:${P}pw`, e.username);
			assert.match([ "luci-base", "unauthenticated" ], e.read);
		});
	});

	it('existing sessions get the new rights once rpcd has reloaded', () => {
		with_rpcd((conn) => {
			let sid = r.marked_session(conn, `sso:${P}live`);
			try {
				write(conn, "set_role", { name: `${P}live`, read: [ "luci-base" ], write: [] });
				let acls = r.acls_of(conn, sid);
				assert.match(false, r.has_marker(conn, sid), "rebuilt from the entry, not kept");
				assert.match(true, acls["access-group luci-base read"] == true, "the entry's access group");
				assert.match(true, acls["ubus uci get"] == true, "the group's expanded calls");
			} catch (e) {
				conn.call("session", "destroy", { ubus_rpc_session: sid });
				die(e);
			}
			conn.call("session", "destroy", { ubus_rpc_session: sid });
		});
	});
});

describe('system: luci-sso ubus object — the unauthenticated group', () => {
	// LuCI calls session.access and luci.getFeatures on every page; the
	// `unauthenticated` group grants them, and without them LuCI reports an
	// expired session. The entry holds it, so a reload keeps it.
	let stores = (label, read, stored) => it(label, () => {
		with_rpcd((conn) => {
			let res = write(conn, "set_role", { name: `${P}u`, read, write: [] });
			assert.match({ role: { name: `${P}u`, read: stored, write: [] } }, res);
			assert.match(stored, entry(`${P}u`).read);
		});
	});

	stores('appends it to a read list without it', [ "luci-base" ], [ "luci-base", "unauthenticated" ]);
	stores('never adds a second copy', [ "unauthenticated", "luci-base" ], [ "unauthenticated", "luci-base" ]);
	stores("keeps a list whose pattern grants it, such as '*'", [ "*" ], [ "*" ]);
	stores('stores it alone for a role that grants nothing else, which is valid', [], [ "unauthenticated" ]);

	it('refuses a read list whose negation denies it, and writes nothing', () => {
		with_rpcd((conn) => {
			let before = r.rpcd_sections();
			assert.match(contains({ error: "INVALID_LIST" }), call(conn, "set_role", { name: `${P}u`, read: [ "*", "!unauth*" ], write: [] }));
			assert.match(before, r.rpcd_sections());
			assert.match(false, call(conn, "list_roles").reload_pending);
		});
	});

	it('a restricted role gets session.access and luci.getFeatures, before and after a reload', () => {
		with_rpcd((conn) => {
			write(conn, "set_role", { name: `${P}u`, read: [ "luci-mod-status-*" ], write: [] });
			let sid = r.marked_session(conn, `sso:${P}u`);
			let has_baseline = (acls) => acls["access-group unauthenticated read"] && acls["ubus session access"] && acls["ubus luci getFeatures"];
			try {
				r.await_reload(conn, () => system("kill -HUP $(pidof rpcd)"));
				assert.match(true, !!has_baseline(r.acls_of(conn, sid)), "rebuilt from the entry, with the group");
				r.await_reload(conn, () => system("kill -HUP $(pidof rpcd)"));
				assert.match(true, !!has_baseline(r.acls_of(conn, sid)), "and again after a second reload");
			} catch (e) {
				conn.call("session", "destroy", { ubus_rpc_session: sid });
				die(e);
			}
			conn.call("session", "destroy", { ubus_rpc_session: sid });
		});
	});
});

describe('system: luci-sso ubus object — reload', () => {
	it('list_roles reports a pending reload from a write until rpcd has reloaded', () => {
		with_rpcd((conn) => {
			assert.match(false, call(conn, "list_roles").reload_pending, "nothing pending before");
			r.await_reload(conn, (c) => {
				call(c, "set_role", { name: `${P}pending`, read: [ "*" ], write: [] });
				assert.match(true, call(c, "list_roles").reload_pending, "pending right after the write");
				call(c, "set_role", { name: `${P}pending`, read: [ "luci-base" ], write: [] });
				assert.match(true, call(c, "list_roles").reload_pending, "a second write shares it");
			});
			assert.match(false, call(conn, "list_roles").reload_pending, "done after the reload");
			assert.match([ "luci-base", "unauthenticated" ], entry(`${P}pending`).read, "the reload came after the last write");
		});
	});

	it('an invalid write schedules no reload', () => {
		with_rpcd((conn) => {
			call(conn, "set_role", { name: "bad-name", read: [], write: [] });
			call(conn, "delete_role", { name: `${P}missing` });
			assert.match(false, call(conn, "list_roles").reload_pending);
		});
	});
});

describe('system: luci-sso ubus object — validation', () => {
	// Each invalid call returns an error and writes nothing.
	let rejects = (label, args, expected) => it(label, () => {
		with_rpcd((conn) => {
			let before = r.rpcd_sections();
			assert.match(expected, call(conn, "set_role", args));
			assert.match(before, r.rpcd_sections(), "nothing is written");
		});
	});

	rejects('rejects a missing name', { read: [], write: [] }, contains({ error: "INVALID_NAME" }));
	rejects('rejects an empty name', { name: "", read: [], write: [] }, contains({ error: "INVALID_NAME" }));
	rejects('rejects a name with characters UCI section names cannot hold', { name: "bad-name", read: [], write: [] }, contains({ error: "INVALID_NAME" }));
	rejects('rejects a name that could escape the prefix', { name: "../root", read: [], write: [] }, contains({ error: "INVALID_NAME" }));
	rejects('rejects a name longer than 32 characters', { name: `${P}${sprintf("%026d", 0)}`, read: [], write: [] },
		contains({ error: "INVALID_NAME" }));
	rejects('rejects a missing list', { name: `${P}x`, read: [] }, contains({ error: "INVALID_LIST", message: "write must be an array of strings" }));
	rejects('rejects a list that is not an array (rpcd checks the type)', { name: `${P}x`, read: "*", write: [] }, { ubus_error: regex(/^Invalid argument/) });
	rejects('rejects an unknown argument (rpcd checks the arguments)', { name: `${P}x`, read: [], write: [], password: "x" }, { ubus_error: regex(/^Invalid argument/) });
	rejects('rejects a non-string entry', { name: `${P}x`, read: [ 1 ], write: [] }, contains({ error: "INVALID_LIST", message: "read[0] is not a string" }));
	rejects('rejects an empty entry', { name: `${P}x`, read: [ "" ], write: [] }, contains({ error: "INVALID_LIST" }));
	rejects('rejects a newline in an entry', { name: `${P}x`, read: [ "luci-base\nlist write *" ], write: [] }, contains({ error: "INVALID_LIST" }));
	rejects('rejects a control character in an entry', { name: `${P}x`, read: [], write: [ "luci\tbase" ] }, contains({ error: "INVALID_LIST", message: "write[0] contains a control character" }));
	rejects('rejects an entry longer than 128 characters', { name: `${P}x`, read: [ sprintf("%0129d", 0) ], write: [] }, contains({ error: "INVALID_LIST" }));
	rejects('rejects more than 128 entries', { name: `${P}x`, read: numbered(129), write: [] }, contains({ error: "INVALID_LIST" }));

	it("accepts rpcd's patterns: globs, character classes and negations", () => {
		with_rpcd((conn) => {
			let lists = { read: [ "*", "luci-?ase", "luci-[a-m]*", "!luci-mod-system-*", "! luci-app-*" ], write: [] };
			assert.match(contains({ role: contains(lists) }), write(conn, "set_role", { name: `${P}glob`, ...lists }));
		});
	});

	it('accepts a name of exactly 32 characters', () => {
		with_rpcd((conn) => {
			let name = `${P}${sprintf("%024d", 0)}`;
			assert.match(contains({ role: contains({ name }) }), write(conn, "set_role", { name, read: [], write: [] }));
			assert.match(`sso:${name}`, entry(name).username);
		});
	});

	it('the other methods validate the name the same way', () => {
		with_rpcd((conn) => {
			assert.match(contains({ error: "INVALID_NAME" }), call(conn, "delete_role", { name: "a b" }));
			assert.match(contains({ error: "INVALID_NAME" }), call(conn, "move_role", { name: "", index: 0 }));
		});
	});
});

describe('system: luci-sso ubus object — list_roles', () => {
	it('lists only luci_sso_* login entries, in config order, with their lists', () => {
		with_rpcd((conn) => {
			r.put_login(`${r.ENTRY_PREFIX}${P}one`, { username: `sso:${P}one`, read: "luci-base" });
			r.put_login(`systest_plain`, { username: "systest", password: "$p$root", read: [ "*" ] });
			r.put_login(`${r.ENTRY_PREFIX}${P}two`, { username: `sso:${P}two`, write: [ "luci-base" ] });
			let cur = r.rpcd_cursor();
			cur.set("rpcd", `${r.ENTRY_PREFIX}${P}notalogin`, "rpcd");
			cur.commit("rpcd");

			let mine = filter(call(conn, "list_roles").roles, (x) => index(x.name, P) == 0);
			assert.match([
				{ name: `${P}one`, read: [ "luci-base" ], write: [] },
				{ name: `${P}two`, read: [], write: [ "luci-base" ] },
			], mine);
		});
	});
});

describe('system: luci-sso ubus object — delete_role', () => {
	it('removes the entry and nothing else', () => {
		with_rpcd((conn) => {
			write(conn, "set_role", { name: `${P}gone`, read: [ "*" ], write: [] });
			let before = others();
			assert.match({ result: true }, write(conn, "delete_role", { name: `${P}gone` }));
			assert.match(null, entry(`${P}gone`));
			assert.match(before, others());
		});
	});

	it('returns NOT_FOUND for a role without an entry, and never touches a same-named login', () => {
		with_rpcd((conn) => {
			let before = r.rpcd_sections();
			assert.match(contains({ error: "NOT_FOUND" }), call(conn, "delete_role", { name: `${P}missing` }));
			// "root" names the stock login's user, not a luci_sso_* section.
			assert.match(contains({ error: "NOT_FOUND" }), call(conn, "delete_role", { name: "root" }));
			assert.match(before, r.rpcd_sections());
		});
	});
});

describe('system: luci-sso ubus object — move_role', () => {
	// Three entries with a foreign section between the first two.
	let setup = (conn) => {
		write(conn, "set_role", { name: `${P}a`, read: [ "a" ], write: [] });
		r.put_login("systest_between", { username: "systest", password: "$p$root" });
		write(conn, "set_role", { name: `${P}b`, read: [ "b" ], write: [] });
		write(conn, "set_role", { name: `${P}c`, read: [ "c" ], write: [] });
	};
	let all_names = (conn) => map(call(conn, "list_roles").roles, (x) => x.name);
	// Section names, with every luci_sso_* entry (the devenv's too) as "sso".
	let layout = () => map(r.rpcd_sections(), (s) => (index(s[".name"], r.ENTRY_PREFIX) == 0) ? "sso" : s[".name"]);

	it('moves an entry to the given position among the luci_sso_* entries; other sections stay put', () => {
		with_rpcd((conn) => {
			setup(conn);
			let before = layout();

			let res = write(conn, "move_role", { name: `${P}c`, index: index(all_names(conn), `${P}a`) });
			assert.match([ `${P}c`, `${P}a`, `${P}b` ], filter(map(res.roles, (x) => x.name), (n) => index(n, P) == 0),
				"the reply lists the new order");
			assert.match([ `${P}c`, `${P}a`, `${P}b` ], sso_names(conn));
			assert.match(before, layout(), "every other section keeps its position");
			assert.match(contains({ read: [ "c" ] }), entry(`${P}c`), "the entry moves with its options");

			write(conn, "move_role", { name: `${P}c`, index: length(all_names(conn)) - 1 });
			assert.match([ `${P}a`, `${P}b`, `${P}c` ], sso_names(conn));
			assert.match(before, layout());
		});
	});

	it('returns NOT_FOUND for a role without an entry and INVALID_INDEX outside the list', () => {
		with_rpcd((conn) => {
			setup(conn);
			let before = r.rpcd_sections();
			let total = length(call(conn, "list_roles").roles);
			assert.match(contains({ error: "NOT_FOUND" }), call(conn, "move_role", { name: `${P}missing`, index: 0 }));
			assert.match(contains({ error: "INVALID_INDEX" }), call(conn, "move_role", { name: `${P}a`, index: total }));
			assert.match(contains({ error: "INVALID_INDEX" }), call(conn, "move_role", { name: `${P}a`, index: -1 }));
			assert.match(contains({ error: "INVALID_INDEX" }), call(conn, "move_role", { name: `${P}a` }));
			assert.match(before, r.rpcd_sections());
		});
	});
});
