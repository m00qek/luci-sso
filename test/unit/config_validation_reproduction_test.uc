import { test, assert, assert_eq } from 'testing';
import * as config_loader from 'luci_sso.config';
import * as Result from 'luci_sso.result';
import * as mock from 'mock';

test('config: logic - reproduction - reject internal_issuer_url with insecure scheme (W3)', () => {
    let mocked = mock.create();
    let mock_uci = {
        "luci-sso": {
            "default": { 
                ".type": "oidc", 
                "enabled": "1", 
                "issuer_url": "https://idp.com",
                "internal_issuer_url": "http://10.0.0.5", // INSECURE
                "client_id": "c1",
                "client_secret": "s1",
                "redirect_uri": "https://r1/callback",
                "clock_tolerance": "300"
            },
            "r1": { ".type": "role", "email": "admin@test.com", "read": ["*"], "write": ["*"] }
        }
    };

    mocked.with_uci(mock_uci, (io) => {
        let res = config_loader.load(io);
        assert(!res.ok, "Should reject insecure internal_issuer_url");
        assert_eq(res.error, "CONFIG_ERROR");
        assert(index(res.details, "internal_issuer_url must use HTTPS") >= 0, "Error message must match");
    });
});
