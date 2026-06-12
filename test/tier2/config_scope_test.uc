import { describe, it, assert, truthy, mock } from 'utest';
import * as config from 'luci_sso.config';
import * as Result from 'luci_sso.result';

describe('config: scope', () => {
	it('load custom scope from UCI', () => {
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

		mock.inject('uci', { data: mock_uci }, (uci) => {
			let res = config.load({ uci: uci.cursor(), log: () => null });
			assert.match(truthy(), Result.is(res));
			assert.match(truthy(), res.ok);
			assert.match("openid email custom_scope", res.data.scope, "Should correctly load custom scope from UCI");
		});
	});

	it('handle missing scope', () => {
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

		mock.inject('uci', { data: mock_uci }, (uci) => {
			let res = config.load({ uci: uci.cursor(), log: () => null });
			assert.match(truthy(), Result.is(res));
			assert.match(truthy(), res.ok);
			assert.match(undefined, res.data.scope, "Scope should be undefined if not in UCI");
		});
	});
});
