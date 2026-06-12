import { describe, it, assert, truthy, has_length, falsy } from 'utest';
import * as ubus from 'luci_sso.ubus';
import * as Result from 'luci_sso.result';
import { with_context } from 'context';

describe('ubus: logic', () => {
	it('get_session success', () => {
		with_context({
			ubus: {
				data: {
					"session:get": (args) => {
						assert.match("sid-123", args.ubus_rpc_session);
						return { values: { oidc_user: "test@example.com", oidc_id_token: "token-abc" } };
					}
				}
			}
		}, (deps) => {
			let res = ubus.get_session(deps, "sid-123");
			assert.match(truthy(), Result.is(res));
			assert.match(truthy(), res.ok);
			assert.match("test@example.com", res.data.oidc_user);
			assert.match("token-abc", res.data.oidc_id_token);
		});
	});

	it('get_session handle missing session', () => {
		with_context({
			ubus: { data: { "session:get": {} } }
		}, (deps) => {
			let res = ubus.get_session(deps, "invalid-sid");
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("SESSION_NOT_FOUND", res.error);
		});
	});

	it('get_session handle invalid SID', () => {
		with_context({ ubus: {} }, (deps) => {
			let res = ubus.get_session(deps, null);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INVALID_SID", res.error);
		});
	});

	it('create_passwordless_session admin wildcard', () => {
		let grants = [];

		with_context({
			fs: {},
			ubus: {
				data: {
					"session:create": { ubus_rpc_session: "sid" },
					"session:grant": (args) => { push(grants, args); return {}; },
					"session:set": () => ({})
				}
			}
		}, (deps) => {
			ubus.create_passwordless_session(deps, "root", { read: ["*"], write: ["*"] }, "a@b.com", "at", "rt", "it");

			let scopes = map(grants, (g) => g.scope);
			assert.match(truthy(), index(scopes, "ubus") != -1);
			assert.match(truthy(), index(scopes, "uci") != -1);
			assert.match(truthy(), index(scopes, "file") != -1);
			assert.match(truthy(), index(scopes, "cgi-io") != -1);
		});
	});

	it('register_token atomicity and full hash (B2)', () => {
		let created_locks = {};

		with_context({
			fs: {
				data: {},
				behavior: {
					mkdir: (path, mode) => {
						if (match(path, /\/tokens\//)) {
							if (created_locks[path]) return false;
							created_locks[path] = true;
						}
						return true;
					}
				}
			}
		}, (deps) => {
			let token = "my-secret-token-123";

			let res1 = ubus.register_token(deps, token);
			assert.match(truthy(), Result.is(res1));
			assert.match(truthy(), res1.ok, "First token registration must succeed");

			let lock_paths = keys(created_locks);
			assert.match(has_length(1), lock_paths, "Should have exactly one token entry");
			let token_id = replace(lock_paths[0], /^.*\//, "");
			assert.match(64, length(token_id), "Token ID must be a full 64-character SHA-256 hex digest");

			let res2 = ubus.register_token(deps, token);
			assert.match(truthy(), Result.is(res2));
			assert.match(falsy(), res2.ok, "Replayed token registration must fail");
			assert.match("TOKEN_REPLAYED", res2.error);

			let res3 = ubus.register_token(deps, token + "new");
			assert.match(truthy(), Result.is(res3));
			assert.match(truthy(), res3.ok, "Different token must succeed");
			assert.match(2, length(keys(created_locks)), "Should have two entries now");
		});
	});
});

describe('ubus: security', () => {
	it('create_passwordless_session generates 256-bit CSRF token (B3)', () => {
		let grants = [];

		with_context({
			ubus: {
				data: {
					"session:create": { ubus_rpc_session: "new-sid" },
					"session:grant": (args) => { push(grants, args); return {}; },
					"session:set": (args) => {
						let token = args.values.token;
						assert.match(truthy(), length(token) >= 43, "CSRF token MUST be at least 256 bits (43+ chars)");
						return {};
					}
				}
			}
		}, (deps) => {
			let res = ubus.create_passwordless_session(deps, "root", { read: ["luci-mod-network"], write: [] }, "user@test.com", "at", "rt", "it");
			assert.match(truthy(), Result.is(res));
			assert.match(truthy(), res.ok);
			assert.match(1, length(grants));
			assert.match("access-group", grants[0].scope);
		});
	});

	it('create_passwordless_session robust ACL parsing (N2)', () => {
		let grants = [];

		with_context({
			fs: {
				data: {
					"/usr/share/rpcd/acl.d/test.json": sprintf("%J", {
						"luci-mod-status": { "description": "Actual ACL" },
						"non-luci": { "comment": "This has luci-fake in value but NOT in key" }
					})
				}
			},
			ubus: {
				data: {
					"session:create": { ubus_rpc_session: "sid" },
					"session:grant": (args) => { push(grants, args); return {}; },
					"session:set": () => ({})
				}
			}
		}, (deps) => {
			ubus.create_passwordless_session(deps, "root", { read: ["*"], write: [] }, "a@b.com", "at", "rt", "it");

			let granted_groups = [];
			for (let g in grants) {
				if (g.scope == "access-group") {
					for (let obj in g.objects) {
						push(granted_groups, obj[0]);
					}
				}
			}

			assert.match(truthy(), index(granted_groups, "luci-mod-status") != -1, "Should grant actual luci-* key");
			assert.match(-1, index(granted_groups, "luci-fake"), "Should NOT grant luci-* string found in values (N2)");
		});
	});
});
