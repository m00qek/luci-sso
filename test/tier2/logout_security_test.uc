import { describe, it, assert, truthy } from 'utest';
import { with_context } from 'context';
import * as router from 'luci_sso.router';
import * as f from 'tier2.fixtures';

describe('logout: security', () => {
	it('robust origin extraction for post_logout_redirect_uri', () => {
		const cases = [
			{
				redirect: "https://trusted-router.local/cgi-bin/luci-sso/callback",
				expected: "https%3A%2F%2Ftrusted-router.local%2F"
			},
			{
				redirect: "https://router:8443/sso/callback",
				expected: "https%3A%2F%2Frouter%3A8443%2F"
			},
			{
				redirect: "https://192.168.1.1/callback?foo=bar",
				expected: "https%3A%2F%2F192.168.1.1%2F"
			}
		];

		for (let c in cases) {
			let config = { ...f.MOCK_CONFIG, redirect_uri: c.redirect };
			let sid = "session-123";
			let stoken = "csrf-token-abc";
			let request = {
				path: "/logout",
				env: { HTTP_HOST: "evil.com" },
				query: { stoken: stoken },
				cookies: { sysauth_https: sid }
			};

			let session_data = {
				"session:get": (args) => {
					assert.match(sid, args.ubus_rpc_session);
					return { values: { token: stoken, oidc_id_token: "hint" } };
				},
				"session:destroy": (args) => {
					assert.match(sid, args.ubus_rpc_session);
					return {};
				}
			};

			with_context({
				fs:          { data: {} },
				ubus:        { data: session_data },
				http_client: { data: {
					"https://trusted.idp/.well-known/openid-configuration": {
						status: 200,
						body: { ...f.MOCK_DISCOVERY, end_session_endpoint: "https://trusted.idp/logout" }
					}
				} },
				clock:       { data: { now: 1516239022 } }
			}, (deps) => {
				let res = router.handle(deps, config, request);
				assert.match(truthy(), res.ok);
				let location = res.data.headers["Location"];

				assert.match(-1, index(location, "evil.com"), `Logout URL MUST NOT contain injected HTTP_HOST (Case: ${c.redirect})`);

				let expected_param = "post_logout_redirect_uri=" + c.expected;
				assert.match(truthy(), index(location, expected_param) != -1, `Should use exact trusted origin base (Expected: ${c.expected}, Got: ${location})`);

				let path_part = replace(c.redirect, /^https:\/\/[^\/]+/, "");
				if (length(path_part) > 1) {
					if (index(path_part, "callback") != -1) {
						assert.match(-1, index(location, "callback"), `Path MUST be stripped from post_logout_redirect_uri (Case: ${c.redirect})`);
					}
				}
			});
		}
	});

	it('ignore insecure end_session_endpoint (W2)', () => {
		let config = f.MOCK_CONFIG;
		let sid = "session-789";
		let stoken = "csrf-token-xyz";
		let request = {
			path: "/logout",
			query: { stoken: stoken },
			cookies: { sysauth_https: sid }
		};

		with_context({
			fs:          { data: {} },
			ubus:        { data: {
				"session:get":    { values: { token: stoken, oidc_id_token: "hint" } },
				"session:destroy": {}
			} },
			http_client: { data: {
				"https://trusted.idp/.well-known/openid-configuration": {
					status: 200,
					body: { ...f.MOCK_DISCOVERY, end_session_endpoint: "http://insecure.idp/logout" }
				}
			} },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let res = router.handle(deps, config, request);
			assert.match(truthy(), res.ok);
			assert.match("/", res.data.headers["Location"], "Should ignore insecure logout endpoint and fallback to local root");
		});
	});
});
