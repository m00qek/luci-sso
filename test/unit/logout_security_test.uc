import { test, assert, assert_eq } from '../testing.uc';
import * as router from 'luci_sso.router';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';

test('logout: security - robust origin extraction for post_logout_redirect_uri', () => {
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

        mock.create()
            .with_ubus({
                "session:get": (args) => {
                    assert_eq(args.ubus_rpc_session, sid);
                    return { values: { token: stoken, oidc_id_token: "hint" } };
                },
                "session:destroy": (args) => {
                    assert_eq(args.ubus_rpc_session, sid);
                    return {};
                }
            })
            .with_responses({
                "https://trusted.idp/.well-known/openid-configuration": {
                    status: 200,
                    body: { ...f.MOCK_DISCOVERY, end_session_endpoint: "https://trusted.idp/logout" }
                }
            })
            .with_env({}, (io) => {
                let res = router.handle(io, config, request);
                let location = res.headers["Location"];
                
                assert(index(location, "evil.com") == -1, `Logout URL MUST NOT contain injected HTTP_HOST (Case: ${c.redirect})`);
                
                let expected_param = "post_logout_redirect_uri=" + c.expected;
                assert(index(location, expected_param) != -1, `Should use exact trusted origin base (Expected: ${c.expected}, Got: ${location})`);
                
                // PARANOID: Ensure the path from redirect_uri is NOT present in the post_logout_redirect_uri
                // We check that the substring AFTER the origin is NOT found within the Location header as part of the redirect param
                let path_part = replace(c.redirect, /^https:\/\/[^\/]+/, "");
                if (length(path_part) > 1) { // If it's more than just "/"
                    // Check if the encoded version of path_part appears after post_logout_redirect_uri
                    // This is a bit complex to test generically, so we just check for "callback" as per the case
                    if (index(path_part, "callback") != -1) {
                         assert(index(location, "callback") == -1, `Path MUST be stripped from post_logout_redirect_uri (Case: ${c.redirect})`);
                    }
                }
            });
    }
});