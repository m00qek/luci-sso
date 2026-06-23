import { describe, it, assert, truthy, mock } from 'utest';
import * as config_loader from 'luci_sso.config';

describe('config: role', () => {
	it('successful load and mapping', () => {
		let mock_uci = {
			"luci-sso": {
				"default": {
					".type": "oidc",
					"enabled": "1",
					"issuer_url": "https://idp.com",
					"client_id": "c1",
					"client_secret": "s1",
					"redirect_uri": "https://r1/callback",
					"clock_tolerance": "300"
				},
				"r1": { ".type": "role", "email": ["admin@test.com"], "read": ["*"], "write": ["*"] },
				"r2": { ".type": "role", "email": ["jane@test.com"], "read": ["luci-mod-network"], "write": [] }
			}
		};

		mock.inject('uci', { data: mock_uci }, (uci) => {
			let config_res = config_loader.load({ uci: uci.cursor(), log: () => null });
			assert.match(truthy(), config_res.ok, "Should load configuration");
			let config = config_res.data;

			assert.match(2, length(config.roles), "Should have 2 roles");
			assert.match("admin@test.com", config.roles[0].emails[0]);
			assert.match("*", config.roles[0].read[0]);
			assert.match("jane@test.com", config.roles[1].emails[0]);
			assert.match("luci-mod-network", config.roles[1].read[0]);
		});
	});

});
