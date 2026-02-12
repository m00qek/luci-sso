import { test, assert, assert_eq, assert_throws } from 'testing';
import * as config_loader from 'luci_sso.config';
import * as mock from 'mock';

test('config: role - successful load and mapping', () => {
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
			"r1": {
				".type": "role",
				"email": ["admin@test.com"],
				"read": ["*"],
				"write": ["*"]
			},
			"r2": {
				".type": "role",
				"email": ["jane@test.com"],
				"read": ["luci-mod-network"],
				"write": []
			}
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let config = config_loader.load(io);
		assert(config, "Should return configuration object");
		assert_eq(length(config.roles), 2, "Should have 2 roles");
		
		assert_eq(config.roles[0].emails[0], "admin@test.com");
		assert_eq(config.roles[0].read[0], "*");
		
		assert_eq(config.roles[1].emails[0], "jane@test.com");
		assert_eq(config.roles[1].read[0], "luci-mod-network");
	});
});

test('config: role - find_roles_for_user merges permissions', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r1": { ".type": "role", "email": ["user@test.com"], "read": ["r1", "shared"], "write": ["w1"] },
			"r2": { ".type": "role", "email": ["user@test.com"], "read": ["r2", "shared"], "write": ["w2"] }
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let config = config_loader.load(io);
		let perms = config_loader.find_roles_for_user(config, { email: "user@test.com" });
		
		assert_eq(length(perms.read), 3, "Should have 3 unique read perms (r1, shared, r2)");
		assert_eq(perms.read[0], "r1");
		assert_eq(perms.read[1], "shared");
		assert_eq(perms.read[2], "r2");
		assert_eq(length(perms.write), 2);
		assert_eq(perms.role_name, "r1", "Should use the first matched role name as identity");
	});
});

test('config: role - first matched role name wins', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r_operator": { ".type": "role", "email": ["user@test.com"], "read": ["r1"], "write": [] },
			"r_admin": { ".type": "role", "email": ["user@test.com"], "read": ["r2"], "write": [] }
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let config = config_loader.load(io);
		let perms = config_loader.find_roles_for_user(config, { email: "user@test.com" });
		
		assert_eq(perms.role_name, "r_operator", "Should use the first matched role name");
	});
});

test('config: role - wildcard expansion check', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r1": { ".type": "role", "email": ["admin@test.com"], "read": ["*"], "write": ["*"] }
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let config = config_loader.load(io);
		let perms = config_loader.find_roles_for_user(config, { email: "admin@test.com" });
		
		assert_eq(perms.read[0], "*");
		assert_eq(perms.write[0], "*");
	});
});

test('config: role - deny user with no roles', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r1": { ".type": "role", "email": ["admin@test.com"], "read": ["*"], "write": ["*"] }
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let config = config_loader.load(io);
		let perms = config_loader.find_roles_for_user(config, { email: "stranger@test.com" });
		
		assert_eq(length(perms.read), 0);
		assert_eq(length(perms.write), 0);
	});
});
