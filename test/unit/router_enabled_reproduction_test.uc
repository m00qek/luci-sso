import { test, assert, assert_eq } from 'testing';
import * as config_loader from 'luci_sso.config';
import * as web_mod from 'luci_sso.web';
import * as router from 'luci_sso.router';
import * as mock from 'mock';

test('router: reproduction - enabled endpoint returns JSON even if disabled (W2)', () => {
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
        assert(res_req.ok);
        let req = res_req.data;

        // 2. Load Config (will be DISABLED)
        let res_c = config_loader.load(io);
        assert(!res_c.ok);
        assert_eq(res_c.error, "DISABLED");

        // 3. Emulate the fix in CGI entry point:
        // If disabled, we still call router.handle(io, null, req)
        let res_router = router.handle(io, null, req);
        
        assert(res_router.ok);
        assert_eq(res_router.data.status, 200);
        assert_eq(res_router.data.body, '{"enabled": false}');
    });
});
