import { test, assert, assert_eq, assert_throws } from 'testing';
import * as config_loader from 'luci_sso.config';
import * as mock from 'mock';

test('config: role - group mapping support', () => {
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
		let config = config_loader.load(io);
		
		// Test developer match
		let perms_dev = config_loader.find_roles_for_user(config, { groups: ["developers", "everyone"] });
		assert_eq(perms_dev.role_name, "r_dev");
		assert_eq(perms_dev.read[0], "git");
		
		// Test operations match
		let perms_ops = config_loader.find_roles_for_user(config, { groups: ["operations"] });
		assert_eq(perms_ops.role_name, "r_ops");
		assert_eq(perms_ops.write[0], "*");
		
		// Test no match
		let perms_none = config_loader.find_roles_for_user(config, { groups: ["marketing"] });
		assert_eq(length(perms_none.read), 0);
	});
});

test('config: role - email OR group match', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r1": { ".type": "role", "email": ["admin@test.com"], "group": ["admins"], "read": ["*"], "write": ["*"] }
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let config = config_loader.load(io);
		
		// Match by email
		let perms_email = config_loader.find_roles_for_user(config, { email: "admin@test.com", groups: ["something-else"] });
		assert_eq(perms_email.role_name, "r1");

		// Match by group
		let perms_group = config_loader.find_roles_for_user(config, { email: "user@test.com", groups: ["admins"] });
		assert_eq(perms_group.role_name, "r1");
	});
});
