import { it, assert, truthy, falsy } from 'utest';
import * as config_loader from 'luci_sso.config';
import * as mock from 'mock';

it('config: role - group mapping support', () => {
	let mocked = mock.create();
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

	mocked.with_uci(mock_uci, (io) => {
		let config = config_loader.load(io).data;
		
		// Test developer match
		let res_dev = config_loader.find_roles_for_user(config, { groups: ["developers", "everyone"] });
		assert.match(truthy(), res_dev.ok, "Should find dev role");
		let perms_dev = res_dev.data;
		assert.match("r_dev", perms_dev.role_name);
		assert.match("git", perms_dev.read[0]);
		
		// Test operations match
		let res_ops = config_loader.find_roles_for_user(config, { groups: ["operations"] });
		assert.match(truthy(), res_ops.ok, "Should find ops role");
		let perms_ops = res_ops.data;
		assert.match("r_ops", perms_ops.role_name);
		assert.match("*", perms_ops.write[0]);
		
		// Test no match
		let res_none = config_loader.find_roles_for_user(config, { groups: ["marketing"] });
		assert.match(falsy(), res_none.ok, "Should NOT find roles");
		assert.match("NO_ROLES_MATCHED", res_none.error);
	});
});

it('config: role - email OR group match', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r1": { ".type": "role", "email": ["admin@test.com"], "group": ["admins"], "read": ["*"], "write": ["*"] }
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let config = config_loader.load(io).data;
		
		// Match by email
		let res_email = config_loader.find_roles_for_user(config, { email: "admin@test.com", groups: ["something-else"] });
		assert.match(truthy(), res_email.ok);
		assert.match("r1", res_email.data.role_name);

		// Match by group
		let res_group = config_loader.find_roles_for_user(config, { email: "user@test.com", groups: ["admins"] });
		assert.match(truthy(), res_group.ok);
		assert.match("r1", res_group.data.role_name);
	});
});
