import { it, assert, truthy, falsy, mock } from 'utest';
import * as config_loader from 'luci_sso.config';

it('config: role - group mapping support', () => {
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
			"r_dev": {
				".type": "role",
				"group": ["developers"],
				"read": ["git"],
				"write": []
			},
			"r_ops": {
				".type": "role",
				"group": ["operations"],
				"read": ["k8s"],
				"write": ["*"]
			}
		}
	};

	mock.inject('uci', { data: mock_uci }, (uci) => {
		let config = config_loader.load({ uci: uci.cursor(), log: () => null }).data;

		let res_dev = config_loader.find_roles_for_user(config, { groups: ["developers", "everyone"] });
		assert.match(truthy(), res_dev.ok, "Should find dev role");
		assert.match("r_dev", res_dev.data.role_name);
		assert.match("git", res_dev.data.read[0]);

		let res_ops = config_loader.find_roles_for_user(config, { groups: ["operations"] });
		assert.match(truthy(), res_ops.ok, "Should find ops role");
		assert.match("r_ops", res_ops.data.role_name);
		assert.match("*", res_ops.data.write[0]);

		let res_none = config_loader.find_roles_for_user(config, { groups: ["marketing"] });
		assert.match(falsy(), res_none.ok, "Should NOT find roles");
		assert.match("NO_ROLES_MATCHED", res_none.error);
	});
});

it('config: role - email OR group match', () => {
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r1": { ".type": "role", "email": ["admin@test.com"], "group": ["admins"], "read": ["*"], "write": ["*"] }
		}
	};

	mock.inject('uci', { data: mock_uci }, (uci) => {
		let config = config_loader.load({ uci: uci.cursor(), log: () => null }).data;

		let res_email = config_loader.find_roles_for_user(config, { email: "admin@test.com", groups: ["something-else"] });
		assert.match(truthy(), res_email.ok);
		assert.match("r1", res_email.data.role_name);

		let res_group = config_loader.find_roles_for_user(config, { email: "user@test.com", groups: ["admins"] });
		assert.match(truthy(), res_group.ok);
		assert.match("r1", res_group.data.role_name);
	});
});
