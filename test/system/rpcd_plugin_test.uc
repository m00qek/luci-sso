import { describe, it, assert } from 'utest';
import * as r from 'lib.rpcd';
import * as fs from 'fs';

// System bucket: the luci-sso ubus object (files/usr/share/rpcd/ucode/luci-sso.uc)
// running inside the container's REAL rpcd, and the ACL that lets the settings
// page reach it. The object writes nothing: role permissions are the roles'
// rpcd login entries, which the page edits as staged UCI changes, so the
// settings ACL grants UCI access to rpcd as well as to luci-sso. That makes
// the luci-app-sso access group root-equivalent, as it always was: whoever
// may edit the roles may give their own email a role with write '*'.

const ACL_DIR = "/usr/share/rpcd/acl.d";
const SETTINGS_ACL = `${ACL_DIR}/luci-app-sso.json`;
const SCRATCH_ACL = `${ACL_DIR}/zz-systest-groups.json`;

function call(conn, method, args) {
	let res = conn.call("luci-sso", method, args || {});
	return (res == null) ? { ubus_error: conn.error() } : res;
}

// The access groups the login knows, computed here independently: every key
// of every acl.d/*.json whose value is an object.
function known_groups() {
	let out = {};
	for (let f in fs.lsdir(ACL_DIR))
		if (match(f, /\.json$/)) {
			let data = null;
			try { data = json(fs.readfile(`${ACL_DIR}/${f}`)); } catch (e) {}
			for (let k, v in (type(data) == "object" ? data : {}))
				if (type(v) == "object") out[k] = true;
		}
	return out;
}

describe('system: luci-sso ubus object — methods', () => {
	it('offers list_acl_groups and the connection test, and nothing that writes', () => {
		let conn = r.connect();
		assert.match([ "list_acl_groups", "test_connection", "test_connection_result" ], sort(keys(conn.list("luci-sso")[0])));
	});
});

describe('system: luci-sso ubus object — list_acl_groups', () => {
	it('lists the access groups the login knows, sorted, each once', () => {
		let expected = filter(sort(keys(known_groups())), (g) => !match(g, /^!|[*?\[]/));
		let res = call(r.connect(), "list_acl_groups");
		assert.match({ groups: expected }, res);
		for (let g in [ "luci-base", "luci-app-sso", "unauthenticated" ])
			assert.match(true, index(res.groups, g) >= 0, g);
	});

	it('leaves out what the login does not grant, and names a role list would read as a pattern', () => {
		fs.writefile(SCRATCH_ACL, sprintf('%J', {
			"systest-ok": { read: { ubus: { "luci-sso": [ "list_acl_groups" ] } } },
			"systest-empty": {},
			"systest-not-an-object": [ "read" ],
			"systest-string": "x",
			"systest[admin]": { read: {} },
			"systest-*": { read: {} },
			"!systest-neg": { read: {} },
		}));
		let res = null;
		try { res = call(r.connect(), "list_acl_groups"); } catch (e) { fs.unlink(SCRATCH_ACL); die(e); }
		fs.unlink(SCRATCH_ACL);
		let mine = filter(res.groups, (g) => index(g, "systest") == 0 || index(g, "!systest") == 0);
		assert.match([ "systest-empty", "systest-ok" ], mine);
	});

	it('changes nothing', () => {
		let before = r.rpcd_sections();
		call(r.connect(), "list_acl_groups");
		assert.match(before, r.rpcd_sections());
	});
});

describe('system: the luci-app-sso ACL', () => {
	let acl = json(fs.readfile(SETTINGS_ACL))["luci-app-sso"];

	it('grants UCI read and write on luci-sso and rpcd, where the roles and their permissions are', () => {
		assert.match([ "luci-sso", "rpcd" ], acl.read.uci);
		assert.match([ "luci-sso", "rpcd" ], acl.write.uci);
	});

	it('grants the luci-sso object only its read-only method and the connection test', () => {
		assert.match({ "luci-sso": [ "list_acl_groups" ] }, acl.read.ubus);
		assert.match({ "luci-sso": [ "test_connection", "test_connection_result" ] }, acl.write.ubus);
	});

	// The delegated administrator: a password login whose only group is
	// luci-app-sso. It may stage changes to both files the settings page
	// edits, and so is root-equivalent; the documentation says so.
	it('a session with only luci-app-sso can stage changes to luci-sso and to rpcd', () => {
		let conn = r.connect(), sid = null, failure = null;
		r.put_login("systest_delegate", { username: "systest_delegate", password: "$p$root", read: [ "luci-app-sso" ], write: [ "luci-app-sso" ] });
		try {
			let login = conn.call("session", "login", { username: "systest_delegate", password: "admin", timeout: 60 });
			assert.match(true, !!login, "password login with only luci-app-sso");
			sid = login.ubus_rpc_session;

			for (let config in [ "luci-sso", "rpcd" ]) {
				conn.call("uci", "add", { ubus_rpc_session: sid, config, type: "login", name: "luci_sso_systest_delegated", values: { username: "sso:systest_delegated" } });
				assert.match(null, conn.error(), `uci add on ${config} is allowed`);
				let staged = conn.call("uci", "changes", { ubus_rpc_session: sid, config });
				assert.match(true, length(staged.changes) > 0, `and staged in ${config}`);
				conn.call("uci", "revert", { ubus_rpc_session: sid, config });
			}
			assert.match(null, r.rpcd_cursor().get("rpcd", "luci_sso_systest_delegated"), "nothing committed");
		} catch (e) {
			failure = e;
		}
		if (sid) conn.call("session", "destroy", { ubus_rpc_session: sid });
		r.drop_section("systest_delegate");
		if (failure != null) die(failure);
	});
});
