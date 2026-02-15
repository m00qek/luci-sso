import { test, assert, assert_eq } from '../testing.uc';
import * as router from 'luci_sso.router';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';

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
            // CURRENT behavior (VULNERABLE): It redirects to https://idp.com/logout...
            assert_eq(res.data.headers["Location"], "/", "Should redirect to root if session is invalid");
        });
});
