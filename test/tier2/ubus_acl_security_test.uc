import { describe, it, assert, truthy } from 'utest';
import * as ubus from 'luci_sso.ubus';
import { with_context } from 'context';

describe('ubus: security', () => {
	it('_grant_all_luci_acls handles malformed ACL files', () => {
		let grants = [];

		with_context({
			fs: {
				data: {
					"/usr/share/rpcd/acl.d/valid.json": sprintf("%J", {
						"luci-base": { "description": "Base permissions" }
					}),
					"/usr/share/rpcd/acl.d/bad.json": "{ invalid json !!! }",
					"/usr/share/rpcd/acl.d/array.json": sprintf("%J", ["luci-broken"]),
					"/usr/share/rpcd/acl.d/invalid_val.json": sprintf("%J", {
						"luci-evil": "not-an-object"
					})
				}
			},
			ubus: {
				data: {
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
				}
			}
		}, (deps) => {
			ubus.create_passwordless_session(deps, "root", { read: ["*"], write: [] }, "a@b.com", "at", "rt", "it");

			assert.match(truthy(), index(grants, "luci-base") != -1, "Should grant valid ACL");
			assert.match(-1, index(grants, "luci-broken"), "Should NOT grant from array root");
			assert.match(-1, index(grants, "luci-evil"), "Should NOT grant if value is not an object (W5)");

			assert.match(truthy(), length(grants) > 0);
		});
	});
});
