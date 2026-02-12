import { test, assert, assert_eq } from '../testing.uc';
import * as config from 'luci_sso.config';
import * as mock from 'mock';

test('config: scope - load custom scope from UCI', () => {
    let mock_uci = {
        "luci-sso": {
            "default": {
                ".type": "oidc",
                "enabled": "1",
                "issuer_url": "https://idp.com",
                "client_id": "client",
                "client_secret": "secret",
                "redirect_uri": "https://router/callback",
                "clock_tolerance": "300",
                "scope": "openid email custom_scope"
            },
            "r1": { ".type": "role", "email": "a@b.com", "read": ["*"], "write": [] }
        }
    };

    mock.create()
        .with_uci(mock_uci)
        .with_env({}, (io) => {
            let cfg = config.load(io);
            assert_eq(cfg.scope, "openid email custom_scope", "Should correctly load custom scope from UCI");
        });
});

test('config: scope - handle missing scope', () => {
    let mock_uci = {
        "luci-sso": {
            "default": {
                ".type": "oidc",
                "enabled": "1",
                "issuer_url": "https://idp.com",
                "client_id": "client",
                "client_secret": "secret",
                "redirect_uri": "https://router/callback",
                "clock_tolerance": "300"
            },
            "r1": { ".type": "role", "email": "a@b.com", "read": ["*"], "write": [] }
        }
    };

    mock.create()
        .with_uci(mock_uci)
        .with_env({}, (io) => {
            let cfg = config.load(io);
            // In the current implementation, cfg.scope will be undefined
            assert(cfg.scope === undefined, "Scope should be undefined if not in UCI");
        });
});
