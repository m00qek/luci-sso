import { test, assert, assert_eq } from 'testing';
import * as router from 'luci_sso.router';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

test('router: logout - DO NOT initiate OIDC logout if local session is invalid', () => {
    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: f.MOCK_CONFIG.issuer_url,
    };

    let discovery_with_logout = { 
        ...f.MOCK_DISCOVERY, 
        end_session_endpoint: "https://idp.com/logout" 
    };

    mock.create()
        .with_responses({
            "https://trusted.idp/.well-known/openid-configuration": { 
                status: 200, 
                body: discovery_with_logout
            }
        })
        .with_ubus({
            // Simulate session not found (expired/invalid)
            "session:get": (args) => { return null; }
        })
        .spy((io) => {
            let request = {
                path: "/logout",
                cookies: { "sysauth_https": "expired-sid" },
                query: { "stoken": "some-token" },
                env: { HTTPS: "on" }
            };

            let res = router.handle(io, test_config, request, {});
            
            assert(res.ok);
            // EXPECTED behavior: Redirect to local root if session is missing.
            assert_eq(res.data.headers["Location"], "/", "Should redirect to root if session is invalid");
        });
});

test('router: security - W3: post_logout_redirect_uri match check', () => {
	let malformed_config = {
		...f.MOCK_CONFIG,
		redirect_uri: "not-a-url" // Will fail the regex match
	};

	let sid = "test-sid";
	let id_token = "test-id-token";

	mock.create()
		.with_responses({
			[`${f.MOCK_CONFIG.issuer_url}/.well-known/openid-configuration`]: { 
				status: 200, 
				body: { ...f.MOCK_DISCOVERY, end_session_endpoint: "https://idp.com/logout" }
			}
		})
		.spy((io) => {
			// Mock ubus session verify
			io.ubus_call = (obj, method, args) => {
				if (obj == "session" && method == "get") {
					return { values: { oidc_id_token: id_token, user: "admin" } };
				}
				return {};
			};

			let request = {
				path: "/logout",
				cookies: { sysauth_https: sid }
			};

			let res = router.handle(io, malformed_config, request);
			
			assert(res.ok, "Should succeed even with malformed redirect_uri");
			let loc = res.data.headers.Location;
			
			// Should default to "/" if regex match fails
			assert(index(loc, "post_logout_redirect_uri=%2F") >= 0, "Should default to safe '/' for malformed URI");
		});
});
