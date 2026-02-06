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

// =============================================================================
// Tier 2: Configuration Logic
// =============================================================================

test('LOGIC: Config - Successful Load & RPCD Sync', () => {
	let mock_data = {
		"rpcd": {
			"s1": { ".type": "login", "username": "admin" }
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
			"u1": { ".type": "user", "rpcd_user": "admin", "rpcd_password": "p1", "email": "admin@test.com" }
		}
	};

	let cursor = create_mock_cursor(mock_data);
	let res = config_loader.load(cursor, {});

	assert(res.ok, "Should load valid configuration");
	assert_eq(res.data.issuer_url, "https://idp.com");
	assert_eq(res.data.user_mappings[0].rpcd_user, "admin");
});

test('LOGIC: Config - Reject Invalid RPCD User', () => {
	let mock_data = {
		"rpcd": {
			"s1": { ".type": "login", "username": "real-user" }
		},
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com" },
			"u1": { ".type": "user", "rpcd_user": "fake-user", "rpcd_password": "p", "email": "test@test.com" }
		}
	};

	let cursor = create_mock_cursor(mock_data);
	let res = config_loader.load(cursor, {});

	assert(res.ok);
	assert_eq(length(res.data.user_mappings), 0, "Mapping for non-existent RPCD user must be ignored");
});

test('LOGIC: Config - Handle Disabled State', () => {
	let mock_data = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "0" }
		}
	};
	let cursor = create_mock_cursor(mock_data);
	let res = config_loader.load(cursor, {});
	assert_eq(res.error, "DISABLED");
});

test('LOGIC: Config - Handle Missing Config', () => {
	let cursor = create_mock_cursor({});
	let res = config_loader.load(cursor, {});
	assert_eq(res.error, "CONFIG_NOT_FOUND");
});
