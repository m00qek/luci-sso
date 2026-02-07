import { test, assert, assert_eq, assert_throws } from 'testing';
import * as config_loader from 'luci_sso.config';
import * as mock from 'mock';

// =============================================================================
// Tier 2: Configuration Logic (Platinum Suite)
// =============================================================================

test('LOGIC: Config - Successful Load & RPCD Sync', () => {
	let mocked = mock.create();
	let mock_uci = {
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
				"redirect_uri": "r1",
				"clock_tolerance": "300"
			},
			"u1": { ".type": "user", "rpcd_user": "admin", "rpcd_password": "p1", "email": "admin@test.com" }
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let config = config_loader.load(io);
		assert(config, "Should return configuration object");
		assert_eq(config.issuer_url, "https://idp.com");
		assert_eq(config.clock_tolerance, 300);
		assert_eq(config.user_mappings[0].rpcd_user, "admin");
	});
});

test('LOGIC: Config - Normalization (Email list vs string)', () => {
	let mocked = mock.create();
	let mock_uci = {
		"rpcd": { "s1": { ".type": "login", "username": "u1" }, "s2": { ".type": "login", "username": "u2" } },
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300" },
			"m1": { ".type": "user", "rpcd_user": "u1", "rpcd_password": "p", "email": "single@test.com" },
			"m2": { ".type": "user", "rpcd_user": "u2", "rpcd_password": "p", "email": ["a@b.com", "c@d.com"] }
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let config = config_loader.load(io);
		assert_eq(type(config.user_mappings[0].emails), "array", "Single email should be wrapped in array");
		assert_eq(length(config.user_mappings[1].emails), 2, "Multiple emails should remain an array");
	});
});

test('LOGIC: Config - HTTPS Enforcement & Localhost Exceptions', () => {
	let mocked = mock.create();
	
	let check = (url) => {
		let mock_uci = {
			"luci-sso": { "default": { ".type": "oidc", "enabled": "1", "issuer_url": url, "clock_tolerance": "300" } }
		};
		return mocked.with_uci(mock_uci, (io) => {
			try { config_loader.load(io); return true; } catch (e) { return false; }
		});
	};

	assert(check("https://idp.com"), "HTTPS should be allowed");
	assert(check("http://localhost:8080"), "http://localhost should be allowed");
	assert(check("http://127.0.0.1"), "http://127.0.0.1 should be allowed");
	assert(!check("http://idp.com"), "Insecure remote HTTP must be rejected");
});

test('LOGIC: Config - Reject Invalid RPCD User', () => {
	let mocked = mock.create();
	let mock_uci = {
		"rpcd": {
			"s1": { ".type": "login", "username": "real-user" }
		},
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300" },
			"u1": { ".type": "user", "rpcd_user": "fake-user", "rpcd_password": "p", "email": "test@test.com" }
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let results = mocked.using(io).spy((spying_io) => {
			let config = config_loader.load(spying_io);
			assert_eq(length(config.user_mappings), 0, "Mapping for non-existent RPCD user must be ignored");
		});
		
		assert(results.called("log", "warn"), "Should log a warning when ignoring an invalid mapping");
	});
});

test('LOGIC: Config - Handle Disabled State', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "0" }
		}
	};
	mocked.with_uci(mock_uci, (io) => {
		assert_throws(() => config_loader.load(io));
	});
});

test('LOGIC: Config - Handle Missing Config', () => {
	let mocked = mock.create();
	mocked.with_uci({}, (io) => {
		assert_throws(() => config_loader.load(io));
	});
});

test('LOGIC: Config - Reject Missing Issuer URL', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "clock_tolerance": "300" }
		}
	};
	mocked.with_uci(mock_uci, (io) => {
		assert_throws(() => config_loader.load(io));
	});
});

test('LOGIC: Config - Reject Missing Clock Tolerance', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com" }
		}
	};
	mocked.with_uci(mock_uci, (io) => {
		assert_throws(() => config_loader.load(io));
	});
});
