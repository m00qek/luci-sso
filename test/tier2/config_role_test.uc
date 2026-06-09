import { it, assert, truthy, falsy, mock } from 'utest';
import * as config_loader from 'luci_sso.config';

it('config: role - successful load and mapping', () => {
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

it('config: role - find_roles_for_user merges permissions', () => {
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r1": { ".type": "role", "email": ["user@test.com"], "read": ["r1", "shared"], "write": ["w1"] },
			"r2": { ".type": "role", "email": ["user@test.com"], "read": ["r2", "shared"], "write": ["w2"] }
		}
	};

	mock.inject('uci', { data: mock_uci }, (uci) => {
		let config = config_loader.load({ uci: uci.cursor(), log: () => null }).data;
		let res = config_loader.find_roles_for_user(config, { email: "user@test.com" });
		assert.match(truthy(), res.ok, "Should find roles");
		let perms = res.data;

		assert.match(3, length(perms.read), "Should have 3 unique read perms (r1, shared, r2)");
		assert.match("r1", perms.read[0]);
		assert.match("shared", perms.read[1]);
		assert.match("r2", perms.read[2]);
		assert.match(2, length(perms.write));
		assert.match("r1", perms.role_name, "Should use the first matched role name as identity");
	});
});

it('config: role - first matched role name wins', () => {
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r_operator": { ".type": "role", "email": ["user@test.com"], "read": ["r1"], "write": [] },
			"r_admin": { ".type": "role", "email": ["user@test.com"], "read": ["r2"], "write": [] }
		}
	};

	mock.inject('uci', { data: mock_uci }, (uci) => {
		let config = config_loader.load({ uci: uci.cursor(), log: () => null }).data;
		let res = config_loader.find_roles_for_user(config, { email: "user@test.com" });
		assert.match(truthy(), res.ok, "Should find roles");
		assert.match("r_operator", res.data.role_name, "Should use the first matched role name");
	});
});

it('config: role - wildcard expansion check', () => {
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r1": { ".type": "role", "email": ["admin@test.com"], "read": ["*"], "write": ["*"] }
		}
	};

	mock.inject('uci', { data: mock_uci }, (uci) => {
		let config = config_loader.load({ uci: uci.cursor(), log: () => null }).data;
		let res = config_loader.find_roles_for_user(config, { email: "admin@test.com" });
		assert.match(truthy(), res.ok, "Should find roles");
		assert.match("*", res.data.read[0]);
		assert.match("*", res.data.write[0]);
	});
});

it('config: role - deny user with no roles', () => {
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r1": { ".type": "role", "email": ["admin@test.com"], "read": ["*"], "write": ["*"] }
		}
	};

	mock.inject('uci', { data: mock_uci }, (uci) => {
		let config = config_loader.load({ uci: uci.cursor(), log: () => null }).data;
		let res = config_loader.find_roles_for_user(config, { email: "stranger@test.com" });
		assert.match(falsy(), res.ok, "Should NOT find roles");
		assert.match("NO_ROLES_MATCHED", res.error);
	});
});
