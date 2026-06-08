import { it, assert, truthy } from 'utest';
import * as config from 'luci_sso.config';
import * as Result from 'luci_sso.result';
import * as mock from 'mock';

it('config: scope - load custom scope from UCI', () => {
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
            let res = config.load(io);
            assert.match(truthy(), Result.is(res));
            assert.match(truthy(), res.ok);
            assert.match("openid email custom_scope", res.data.scope, "Should correctly load custom scope from UCI");
        });
});

it('config: scope - handle missing scope', () => {
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
            let res = config.load(io);
            assert.match(truthy(), Result.is(res));
            assert.match(truthy(), res.ok);
            // In the current implementation, res.data.scope will be undefined
            assert.match(truthy(), res.data.scope === undefined, "Scope should be undefined if not in UCI");
        });
});
