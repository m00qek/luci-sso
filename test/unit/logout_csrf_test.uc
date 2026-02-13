import { test, assert, assert_eq } from '../testing.uc';
import * as router from 'luci_sso.router';
import * as mock from '../mock.uc';
import * as f from './tier2_fixtures.uc';

// B3: CSRF Token Validation Test
test('logout: security - csrf token validation', () => {
	let config = { ...f.MOCK_CONFIG };
	let session_token = "valid-csrf-token-123";
	let sid = "session-id-xyz";
	let mock_session = { values: { token: session_token, oidc_id_token: "mock-id-token" } };

    let discovery_response = {
        "https://trusted.idp/.well-known/openid-configuration": {
            status: 200,
            body: f.MOCK_DISCOVERY
        }
    };

	// 1. Missing Token -> Fail (403)
	mock.create()
		.with_ubus({ "session:get": mock_session })
        .with_responses(discovery_response)
		.with_env({}, (io) => {
			let req = {
				path: "/logout",
				cookies: { sysauth: sid },
				query: {}
			};
			let res = router.handle(io, config, req);
			assert_eq(res.status, 403, "Logout without token MUST fail");
		});

	// 2. Wrong Token -> Fail (403)
	mock.create()
		.with_ubus({ "session:get": mock_session })
        .with_responses(discovery_response)
		.with_env({}, (io) => {
			let req = {
				path: "/logout",
				cookies: { sysauth: sid },
				query: { stoken: "wrong-token" }
			};
			let res = router.handle(io, config, req);
			assert_eq(res.status, 403, "Logout with wrong token MUST fail");
		});

	// 3. Correct Token -> Success (302)
	let history = mock.create()
		.with_ubus({ 
			"session:get": mock_session,
			"session:destroy": {} 
		})
		.with_responses(discovery_response)
		.spy((io) => {
			let req = {
				path: "/logout",
				cookies: { sysauth: sid },
				query: { stoken: session_token }
			};
			let res = router.handle(io, config, req);
			assert_eq(res.status, 302, "Logout with correct token MUST succeed");
		});
	
	assert(history.called("ubus", "session", "destroy"), "Session MUST be destroyed on valid logout");

	// 4. Session Lookup Fails -> Should NOT call destroy (W1 fix verification)
	history = mock.create()
		.with_ubus({ 
			"session:get": { error: 404 }, // Session not found
			"session:destroy": {} 
		})
		.with_responses(discovery_response)
		.spy((io) => {
			let req = {
				path: "/logout",
				cookies: { sysauth: "invalid-sid" },
				query: { stoken: "any" }
			};
			router.handle(io, config, req);
		});
	
	assert(!history.called("ubus", "session", "destroy"), "Should NOT call destroy if session lookup failed (W1)");
});
