import { test, assert, assert_eq } from 'testing';
import * as config_loader from 'luci_sso.config';

/**
 * Mocks a UCI cursor for testing config logic.
 */
function create_mock_cursor(data) {
	return {
		get_all: function(pkg, sec) {
			return data[pkg] && data[pkg][sec] ? data[pkg][sec] : null;
		},
		foreach: function(pkg, type, cb) {
			if (!data[pkg]) return;
			for (let name, section in data[pkg]) {
				if (section[".type"] === type) {
					cb(section);
				}
			}
		}
	};
}

test('Config: Load - Successful validation with RPCD', () => {
	let mock_data = {
		"rpcd": {
			"s1": { ".type": "login", "username": "admin" },
			"s2": { ".type": "login", "username": "guest" }
		},
		"luci-sso": {
			"default": { 
				".type": "oidc", 
				"enabled": "1", 
				"issuer_url": "https://idp.com",
				"client_id": "c1",
				"client_secret": "s1",
				"redirect_uri": "r1"
			},
			"u1": { ".type": "user", "rpcd_user": "admin", "rpcd_password": "p1", "email": "admin@test.com" },
			"u2": { ".type": "user", "rpcd_user": "guest", "rpcd_password": "p2", "email": ["g1@test.com", "g2@test.com"] }
		}
	};

	let cursor = create_mock_cursor(mock_data);
	let res = config_loader.load(cursor, {});

	assert(res.ok, "Should load successfully");
	assert_eq(res.data.issuer_url, "https://idp.com");
	assert_eq(length(res.data.user_mappings), 2);
	assert_eq(res.data.user_mappings[0].rpcd_user, "admin");
});

test('Config: Load - Reject mappings for non-existent RPCD users', () => {
	let mock_data = {
		"rpcd": {
			"s1": { ".type": "login", "username": "real-admin" }
		},
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com" },
			"u1": { ".type": "user", "rpcd_user": "fake-user", "rpcd_password": "p", "email": "test@test.com" },
			"u2": { ".type": "user", "rpcd_user": "real-admin", "rpcd_password": "p", "email": "admin@test.com" }
		}
	};

	let logs = [];
	let io = { log: (lvl, msg) => push(logs, msg) };
	let cursor = create_mock_cursor(mock_data);
	let res = config_loader.load(cursor, io);

	assert(res.ok);
	assert_eq(length(res.data.user_mappings), 1, "Should only have one valid mapping");
	assert_eq(res.data.user_mappings[0].rpcd_user, "real-admin");
});

test('Config: Load - Handle disabled SSO', () => {
	let mock_data = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "0" }
		}
	};
	let cursor = create_mock_cursor(mock_data);
	let res = config_loader.load(cursor, {});
	assert_eq(res.error, "DISABLED");
});

test('Config: Load - Handle missing configuration', () => {
	let cursor = create_mock_cursor({});
	let res = config_loader.load(cursor, {});
	assert_eq(res.error, "CONFIG_NOT_FOUND");
});