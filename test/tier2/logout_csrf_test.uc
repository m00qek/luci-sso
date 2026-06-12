import { describe, it, assert, truthy, falsy, spy } from 'utest';
import * as router from 'luci_sso.router';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';

const DISCOVERY_DATA = {
	"https://trusted.idp/.well-known/openid-configuration": {
		status: 200, body: f.MOCK_DISCOVERY
	}
};

describe('logout: security', () => {
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

	it('B1 CSRF bypass regression', () => {
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
