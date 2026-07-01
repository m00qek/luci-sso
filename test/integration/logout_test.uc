import { describe, it, assert, truthy, falsy, spy } from 'utest';
import * as router from 'luci_sso.router';
import { with_context } from 'context';
import * as f from 'fixtures.oidc';

// Integration bucket — the logout flow, entered at router.handle(deps, config,
// request) with a full deps graph (with_context). Covers RP-initiated logout,
// CSRF (stoken) enforcement, session destruction, and safe derivation of the
// post_logout_redirect_uri. Consolidates the tier3 router-logout block plus the
// tier2 logout_* reproductions.

const TEST_POLICY = { allowed_algs: ["RS256"] };

// Local config/discovery for the RP-initiated scenarios (idp.com issuer).
const MOCK_CONFIG = {
	...f.MOCK_CONFIG,
	issuer_url:          "https://idp.com",
	internal_issuer_url: "https://idp.com",
	redirect_uri:        "https://router/callback",
};

const MOCK_DISC_DOC = {
	...f.MOCK_DISCOVERY,
	issuer:                 "https://idp.com",
	authorization_endpoint: "https://idp.com/auth",
	token_endpoint:         "https://idp.com/token",
	jwks_uri:               "https://idp.com/jwks",
};

function mock_request(path, query, cookies, env) {
	return { path: path || "/", query: query || {}, cookies: cookies || {}, env: env || {} };
}

// ─── RP-initiated logout ──────────────────────────────────────────────────────

describe('logout: RP-initiated', () => {
	it('redirects to the IdP end_session_endpoint with id_token_hint and exact post_logout_redirect_uri', () => {
		let ubus_get_called = false;
		let ubus_destroy_called = false;
		let DISC_WITH_LOGOUT = { ...MOCK_DISC_DOC, end_session_endpoint: "https://idp.com/logout" };

		with_context({
			fs: { data: {} },
			ubus: {
				data: {
					"session:get": (args) => { ubus_get_called = true; return { values: { oidc_id_token: "mock-id-token", token: "csrf-123" } }; },
					"session:destroy": (args) => { ubus_destroy_called = true; return {}; }
				}
			},
			http_client: {
				data: { "https://idp.com/.well-known/openid-configuration": { status: 200, body: DISC_WITH_LOGOUT } }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let req = mock_request("/logout", { stoken: "csrf-123" }, { "sysauth": "session-12345" }, { HTTP_HOST: "router.lan" });
			let res = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);

			assert.match(truthy(), res.ok);
			assert.match(302, res.data.status);
			assert.match(0, index(res.data.headers["Location"], "https://idp.com/logout"), "Should redirect to IdP logout");
			assert.match(truthy(), index(res.data.headers["Location"], "id_token_hint=mock-id-token") != -1, "Should include id_token_hint");
			assert.match(truthy(), match(res.data.headers["Location"], /post_logout_redirect_uri=https%3A%2F%2Frouter%2F(&|$)/), "Should include EXACT post_logout_redirect_uri");
		});

		assert.match(truthy(), ubus_get_called, "Should have retrieved session for id_token_hint");
		assert.match(truthy(), ubus_destroy_called, "Should have destroyed local session");
	});

	it('falls back to local logout when the IdP has no end_session_endpoint', () => {
		let ubus_destroy_called = false;

		with_context({
			fs: { data: {} },
			ubus: {
				data: {
					"session:get": (args) => ({ values: { token: "csrf-456" } }),
					"session:destroy": (args) => { ubus_destroy_called = true; return {}; }
				}
			},
			http_client: {
				data: { "https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC } }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let req = mock_request("/logout", { stoken: "csrf-456" }, { "sysauth": "session-12345" });
			let res = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);
			assert.match(truthy(), res.ok);
			assert.match(302, res.data.status);
			assert.match("/", res.data.headers["Location"]);
		});

		assert.match(truthy(), ubus_destroy_called);
	});

	it('redirects an unauthenticated logout to root without hitting the IdP', () => {
		let DISC_WITH_LOGOUT = { ...MOCK_DISC_DOC, end_session_endpoint: "https://idp.com/logout" };

		with_context({
			fs: { data: {} },
			http_client: {
				data: { "https://idp.com/.well-known/openid-configuration": { status: 200, body: DISC_WITH_LOGOUT } }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let req = mock_request("/logout", {}, {}, { HTTP_HOST: "router.lan" });
			let res = router.handle(deps, MOCK_CONFIG, req, TEST_POLICY);

			assert.match(truthy(), res.ok);
			assert.match(302, res.data.status);
			assert.match("/", res.data.headers["Location"], "Should redirect to root for unauthenticated logout");
		});
	});
});

// ─── CSRF (stoken) enforcement ────────────────────────────────────────────────

const DISCOVERY_DATA = {
	"https://trusted.idp/.well-known/openid-configuration": {
		status: 200, body: f.MOCK_DISCOVERY
	}
};

describe('logout: CSRF protection', () => {
	it('csrf token validation', () => {
		let config = { ...f.MOCK_CONFIG };
		let session_token = "valid-csrf-token-123";
		let sid = "session-id-xyz";
		let mock_session = { values: { token: session_token, oidc_id_token: "mock-id-token" } };

		// 1. Missing Token -> Fail (403)
		with_context({
			fs:          { data: {} },
			ubus:        { data: { "session:get": mock_session } },
			http_client: { data: DISCOVERY_DATA },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let req = { path: "/logout", cookies: { sysauth: sid }, query: {} };
			let res = router.handle(deps, config, req);
			assert.match(falsy(), res.ok);
			assert.match(403, res.details.http_status, "Logout without token MUST fail");
		});

		// 2. Wrong Token -> Fail (403)
		with_context({
			fs:          { data: {} },
			ubus:        { data: { "session:get": mock_session } },
			http_client: { data: DISCOVERY_DATA },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let req = { path: "/logout", cookies: { sysauth: sid }, query: { stoken: "wrong-token" } };
			let res = router.handle(deps, config, req);
			assert.match(falsy(), res.ok);
			assert.match(403, res.details.http_status, "Logout with wrong token MUST fail");
		});

		// 3. Correct Token -> Success (302)
		let ubus_calls3 = null;
		with_context({
			fs:          { data: {} },
			ubus:        { data: { "session:get": mock_session, "session:destroy": {} } },
			http_client: { data: DISCOVERY_DATA },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let req = { path: "/logout", cookies: { sysauth: sid }, query: { stoken: session_token } };
			let res = router.handle(deps, config, req);
			assert.match(truthy(), res.ok, "Logout with correct token MUST succeed");
			assert.match(302, res.data.status);
			ubus_calls3 = spy(deps.ubus).calls.call || [];
		});

		let destroy_called = false;
		for (let c in ubus_calls3) {
			if (c[0] === "session" && c[1] === "destroy") { destroy_called = true; break; }
		}
		assert.match(truthy(), destroy_called, "Session MUST be destroyed on valid logout");

		// 4. Session Lookup Fails -> Should NOT call destroy (W1 fix verification)
		let ubus_calls4 = null;
		with_context({
			fs:          { data: {} },
			ubus:        { data: { "session:get": { error: 404 }, "session:destroy": {} } },
			http_client: { data: DISCOVERY_DATA },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let req = { path: "/logout", cookies: { sysauth: "invalid-sid" }, query: { stoken: "any" } };
			router.handle(deps, config, req);
			ubus_calls4 = spy(deps.ubus).calls.call || [];
		});

		let destroy_called4 = false;
		for (let c in ubus_calls4) {
			if (c[0] === "session" && c[1] === "destroy") { destroy_called4 = true; break; }
		}
		assert.match(falsy(), destroy_called4, "Should NOT call destroy if session lookup failed (W1)");
	});

	it('B1 CSRF bypass regression (empty tokens must not match)', () => {
		let config = { ...f.MOCK_CONFIG };
		let sid = "session-id-with-missing-token";
		let mock_session_no_token = { values: { oidc_id_token: "mock-id-token" } };

		with_context({
			fs:          { data: {} },
			ubus:        { data: { "session:get": mock_session_no_token } },
			http_client: { data: { "https://trusted.idp/.well-known/openid-configuration": { status: 200, body: f.MOCK_DISCOVERY } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let req = { path: "/logout", cookies: { sysauth: sid }, query: { stoken: "" } };
			let res = router.handle(deps, config, req);
			assert.match(falsy(), res.ok, "B1: Logout with MISSING session token and MISSING query token MUST fail (CSRF bypass)");
			assert.match(403, res.details.http_status, "B1: Expected 403 Forbidden for empty CSRF token comparison");
		});
	});
});

// ─── post-logout redirect origin safety ───────────────────────────────────────

describe('logout: post-logout redirect origin', () => {
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

	it('ignores an insecure end_session_endpoint and falls back to local root (W2)', () => {
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

// ─── invalid session & malformed redirect_uri ─────────────────────────────────

describe('logout: invalid session and malformed redirect', () => {
	it('B1: redirects to root when the session is invalid', () => {
		let test_config = { ...f.MOCK_CONFIG, issuer_url: "https://trusted.idp" };
		let discovery_with_logout = { ...f.MOCK_DISCOVERY, end_session_endpoint: "https://idp.com/logout" };

		with_context({
			fs:          { data: {} },
			ubus:        { data: { "session:get": () => null } },
			http_client: { data: {
				"https://trusted.idp/.well-known/openid-configuration": {
					status: 200, body: discovery_with_logout
				}
			} },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let request = {
				path: "/logout",
				cookies: { "sysauth_https": "expired-sid" },
				query: { "stoken": "some-token" },
				env: { HTTPS: "on" }
			};
			let res = router.handle(deps, test_config, request, {});
			assert.match(truthy(), res.ok);
			assert.match("/", res.data.headers["Location"], "Should redirect to root if session is invalid");
		});
	});

	it('W3: omits post_logout_redirect_uri when redirect_uri is malformed', () => {
		let malformed_config = { ...f.MOCK_CONFIG, redirect_uri: "not-a-url" };
		let sid = "test-sid";
		let id_token = "test-id-token";

		with_context({
			fs:          { data: {} },
			ubus:        { data: {
				"session:get": { values: { token: "valid-stoken", oidc_id_token: id_token, user: "admin" } },
				"session:destroy": {}
			} },
			http_client: { data: {
				[`${f.MOCK_CONFIG.issuer_url}/.well-known/openid-configuration`]: {
					status: 200, body: { ...f.MOCK_DISCOVERY, end_session_endpoint: "https://idp.com/logout" }
				}
			} },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let request = {
				path: "/logout",
				cookies: { sysauth_https: sid },
				query: { stoken: "valid-stoken" }
			};
			let res = router.handle(deps, malformed_config, request);
			assert.match(truthy(), res.ok, "Should succeed even with malformed redirect_uri");
			let loc = res.data.headers.Location;
			assert.match(-1, index(loc, "post_logout_redirect_uri="), "Should OMIT post_logout_redirect_uri for malformed URI");
		});
	});
});

// ─── redirect derivation robustness (← router_logout_redirect) ─────────────────

describe('logout: redirect derivation robustness', () => {
	it('W3: derives post_logout_redirect_uri origin from a valid redirect_uri, omits it for an invalid scheme', () => {
		let DISC = { ...MOCK_DISC_DOC, end_session_endpoint: "https://idp.com/logout" };
		let session_data = {
			"session:get": (args) => ({ values: { oidc_id_token: "hint", token: "csrf" } }),
			"session:destroy": {}
		};
		let discovery_data = {
			"https://idp.com/.well-known/openid-configuration": { status: 200, body: DISC }
		};

		with_context({
			fs:          { data: {} },
			ubus:        { data: session_data },
			http_client: { data: discovery_data },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let config = { issuer_url: "https://idp.com", redirect_uri: "https://router.lan/cgi-bin/luci-sso/callback" };
			let req = { path: "/logout", query: { stoken: "csrf" }, cookies: { sysauth: "sid" } };
			let res = router.handle(deps, config, req, TEST_POLICY);
			assert.match(truthy(), res.ok);
			assert.match(truthy(), index(res.data.headers["Location"], "post_logout_redirect_uri=https%3A%2F%2Frouter.lan%2F") != -1);
		});

		with_context({
			fs:          { data: {} },
			ubus:        { data: session_data },
			http_client: { data: discovery_data },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let config = { issuer_url: "https://idp.com", redirect_uri: "ftp://router.lan/callback" };
			let req = { path: "/logout", query: { stoken: "csrf" }, cookies: { sysauth: "sid" } };
			let res = router.handle(deps, config, req, TEST_POLICY);
			assert.match(truthy(), res.ok);
			assert.match(-1, index(res.data.headers["Location"], "post_logout_redirect_uri="), "Should OMIT post_logout_redirect_uri for invalid redirect_uri scheme");
		});
	});
});
