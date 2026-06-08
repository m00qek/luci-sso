import { it, assert, truthy } from 'utest';
import * as Result from 'luci_sso.result';
import * as router from 'luci_sso.router';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

it('router: security - B1: handle invalid session during logout', () => {
    let test_config = {
        ...f.MOCK_CONFIG,
        issuer_url: "https://trusted.idp"
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

            assert.match(truthy(), res.ok);
            // EXPECTED behavior: Redirect to local root if session is missing.
            assert.match("/", res.data.headers["Location"], "Should redirect to root if session is invalid");
        });
});

it('router: security - W3: post_logout_redirect_uri match check', () => {
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
					return Result.ok({ values: { token: "valid-stoken", oidc_id_token: id_token, user: "admin" } });
				}
				return Result.ok({});
			};

			let request = {
				path: "/logout",
				cookies: { sysauth_https: sid },
				query: { stoken: "valid-stoken" }
			};

			let res = router.handle(io, malformed_config, request);

			assert.match(truthy(), res.ok, "Should succeed even with malformed redirect_uri");
			let loc = res.data.headers.Location;

			// Should default to "/" if regex match fails
			assert.match(truthy(), index(loc, "post_logout_redirect_uri=") == -1, "Should OMIT post_logout_redirect_uri for malformed URI");
		});
});
