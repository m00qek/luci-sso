import { test, assert, assert_eq } from 'testing';
import * as ubus from 'luci_sso.ubus';
import * as mock from 'mock';

test('ubus: logic - get_session success', () => {
	let factory = mock.create().with_ubus({
		"session:get": (args) => {
			assert_eq(args.ubus_rpc_session, "sid-123");
			return { values: { oidc_user: "test@example.com", oidc_id_token: "token-abc" } };
		}
	});

	factory.with_env({}, (io) => {
		let res = ubus.get_session(io, "sid-123");
		assert(res.ok);
		assert_eq(res.data.oidc_user, "test@example.com");
		assert_eq(res.data.oidc_id_token, "token-abc");
	});
});

test('ubus: logic - get_session handle missing session', () => {
	let factory = mock.create().with_ubus({
		"session:get": (args) => null
	});

	factory.with_env({}, (io) => {
		let res = ubus.get_session(io, "invalid-sid");
		assert(!res.ok);
		assert_eq(res.error, "SESSION_NOT_FOUND");
	});
});

test('ubus: logic - get_session handle invalid SID', () => {
	let factory = mock.create();
	factory.with_env({}, (io) => {
		let res = ubus.get_session(io, null);
		assert(!res.ok);
		assert_eq(res.error, "INVALID_SID");
	});
});

test('ubus: security - create_passwordless_session generates 256-bit CSRF token (B3)', () => {
	let grants = [];
	let factory = mock.create().with_ubus({
		"session:create": { ubus_rpc_session: "new-sid" },
		"session:grant": (args) => { push(grants, args); return {}; },
		"session:set": (args) => {
			let token = args.values.token;
			// 256 bits = 32 bytes. Base64URL encoding 32 bytes = 43 chars
			assert(length(token) >= 43, "CSRF token MUST be at least 256 bits (43+ chars)");
			return {};
		}
	});

	factory.with_env({}, (io) => {
		let res = ubus.create_passwordless_session(io, "root", { read: ["luci-mod-network"], write: [] }, "user@test.com", "at", "rt", "it");
		assert(res.ok);
		assert_eq(length(grants), 1);
		assert_eq(grants[0].scope, "access-group");
	});
});

test('ubus: logic - create_passwordless_session admin wildcard', () => {
	let grants = [];
	let factory = mock.create().with_ubus({
		"session:create": { ubus_rpc_session: "sid" },
		"session:grant": (args) => { push(grants, args); return {}; },
		"session:set": () => ({})
	});

	factory.with_env({}, (io) => {
		ubus.create_passwordless_session(io, "root", { read: ["*"], write: ["*"] }, "a@b.com", "at", "rt", "it");
		
		let scopes = map(grants, (g) => g.scope);
		assert(index(scopes, "ubus") != -1);
		assert(index(scopes, "uci") != -1);
		assert(index(scopes, "file") != -1);
		assert(index(scopes, "cgi-io") != -1);
	});
});

test('ubus: logic - register_token atomicity and full hash (B2)', () => {
	let factory = mock.create().with_files({});
	
	factory.with_env({}, (io) => {
		let token = "my-secret-token-123";
		
		// 1. First registration should succeed
		assert(ubus.register_token(io, token), "First token registration must succeed");
		
		// 2. Verify it created a 64-character hex ID entry
		let files = io.lsdir("/var/run/luci-sso/tokens");
		assert(length(files) == 1, "Should have exactly one token entry");
		assert_eq(length(files[0]), 64, "Token ID must be a full 64-character SHA-256 hex digest");
		
		// 3. Second registration of SAME token must fail (replay)
		assert(!ubus.register_token(io, token), "Replayed token registration must fail");
		
		// 4. Registration of DIFFERENT token should succeed
		assert(ubus.register_token(io, token + "new"), "Different token must succeed");
		assert_eq(length(io.lsdir("/var/run/luci-sso/tokens")), 2, "Should have two entries now");
	});
});

test('ubus: security - create_passwordless_session robust ACL parsing (N2)', () => {
	let grants = [];
	let factory = mock.create().with_ubus({
		"session:create": { ubus_rpc_session: "sid" },
		"session:grant": (args) => { push(grants, args); return {}; },
		"session:set": () => ({})
	}).with_files({
		"/usr/share/rpcd/acl.d/test.json": sprintf("%J", {
			"luci-mod-status": { "description": "Actual ACL" },
			"non-luci": { "comment": "This has luci-fake in value but NOT in key" }
		})
	});

	factory.with_env({}, (io) => {
		ubus.create_passwordless_session(io, "root", { read: ["*"], write: [] }, "a@b.com", "at", "rt", "it");
		
		let granted_groups = [];
		for (let g in grants) {
			if (g.scope == "access-group") {
				for (let obj in g.objects) {
					push(granted_groups, obj[0]);
				}
			}
		}
		
		assert(index(granted_groups, "luci-mod-status") != -1, "Should grant actual luci-* key");
		assert(index(granted_groups, "luci-fake") == -1, "Should NOT grant luci-* string found in values (N2)");
	});
});
