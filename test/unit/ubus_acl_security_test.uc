import { test, assert, assert_eq } from 'testing';
import * as ubus from 'luci_sso.ubus';
import * as mock from 'mock';

test('ubus: security - _grant_all_luci_acls handles malformed ACL files', () => {
	let grants = [];
	let factory = mock.create().with_ubus({
		"session:create": { ubus_rpc_session: "sid" },
		"session:grant": (args) => { 
			if (args.scope == "access-group") {
				for (let obj in args.objects) {
					push(grants, obj[0]);
				}
			}
			return {}; 
		},
		"session:set": () => ({})
	}).with_files({
		// 1. Valid ACL
		"/usr/share/rpcd/acl.d/valid.json": sprintf("%J", {
			"luci-base": { "description": "Base permissions" }
		}),
		// 2. Malformed JSON
		"/usr/share/rpcd/acl.d/bad.json": "{ invalid json !!! }",
		// 3. Not an object at root
		"/usr/share/rpcd/acl.d/array.json": sprintf("%J", ["luci-broken"]),
		// 4. Key matches but value is not an object (Invalid RPCD schema)
		"/usr/share/rpcd/acl.d/invalid_val.json": sprintf("%J", {
			"luci-evil": "not-an-object"
		})
	});

	factory.with_env({}, (io) => {
		ubus.create_passwordless_session(io, "root", { read: ["*"], write: [] }, "a@b.com", "at", "rt", "it");
		
		assert(index(grants, "luci-base") != -1, "Should grant valid ACL");
		assert(index(grants, "luci-broken") == -1, "Should NOT grant from array root");
		assert(index(grants, "luci-evil") == -1, "Should NOT grant if value is not an object (W5)");
		
		// Ensure it didn't crash on bad JSON
		assert(length(grants) > 0);
	});
});
