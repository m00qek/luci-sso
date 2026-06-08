import { it, assert, truthy, falsy } from 'utest';
import * as config_loader from 'luci_sso.config';
import * as web_mod from 'luci_sso.web';
import * as router from 'luci_sso.router';
import * as mock from 'mock';

it('router: reproduction - enabled endpoint returns JSON even if disabled (W2)', () => {
    let factory = mock.create();
    let mock_uci = {
        "luci-sso": {
            "default": { ".type": "oidc", "enabled": "0" } // DISABLED
        }
    };

    factory.with_uci(mock_uci, (io) => {
        // Mock the environment for request parsing
        io.getenv = (k) => {
            if (k == "PATH_INFO") return "/";
            if (k == "QUERY_STRING") return "action=enabled";
            if (k == "HTTP_HOST") return "luci.test";
            return null;
        };

        // 1. Parse Request
        let res_req = web_mod.request(io);
        assert.match(truthy(), res_req.ok);
        let req = res_req.data;

        // 2. Load Config (will be SSO_DISABLED)
        let res_c = config_loader.load(io);
        assert.match(falsy(), res_c.ok);
        assert.match("SSO_DISABLED", res_c.error);

        // 3. Emulate the fix in CGI entry point:
        // If disabled, we still call router.handle(io, null, req)
        let res_router = router.handle(io, null, req);
        
        assert.match(truthy(), res_router.ok, "Action 'enabled' MUST succeed even without config");
        assert.match(200, res_router.data.status);
        assert.match('{"enabled": false}', res_router.data.body);
    });
});

it('router: security - null config guard (B2)', () => {
    mock.create().spy((io) => {
        // Ensure request is fully populated
        let req = { 
            path: "/", 
            query: {},
            cookies: {},
            headers: {}
        };
        
        let res = router.handle(io, null, req);
        
        assert.match(falsy(), res.ok, "Should fail when config is null");
        assert.match("SSO_DISABLED", res.error);
        assert.match(503, res.details.http_status);
    });
});
