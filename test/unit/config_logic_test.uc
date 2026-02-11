import { test, assert, assert_eq, assert_throws } from 'testing';
import * as config_loader from 'luci_sso.config';
import * as mock from 'mock';

// =============================================================================
// Tier 2: Configuration Logic (Platinum Suite)
// =============================================================================

test('config: logic - successful load & RPCD sync', () => {
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
				"redirect_uri": "https://r1",
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

test('config: logic - normalization (email list vs string)', () => {
	let mocked = mock.create();
	let mock_uci = {
		"rpcd": { "s1": { ".type": "login", "username": "u1" }, "s2": { ".type": "login", "username": "u2" } },
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r" },
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

test('config: logic - HTTPS enforcement', () => {
	let mocked = mock.create();
	
	let check = (url) => {
		let mock_uci = {
			"rpcd": { "s1": { ".type": "login", "username": "admin" } },
			"luci-sso": { 
				"default": { ".type": "oidc", "enabled": "1", "issuer_url": url, "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r" },
				"u1": { ".type": "user", "rpcd_user": "admin", "rpcd_password": "p", "email": "a@b.com" }
			}
		};
		return mocked.with_uci(mock_uci, (io) => {
			try { config_loader.load(io); return true; } catch (e) { return false; }
		});
	};

	assert(check("https://idp.com"), "HTTPS should be allowed");
	assert(!check("http://idp.com"), "Insecure remote HTTP must be rejected");
});

test('config: logic - reject empty or invalid user mappings (W5)', () => {
	let mocked = mock.create();
	
	// Case 1: No user sections at all
	let mock_uci_1 = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r" }
		}
	};
	mocked.with_uci(mock_uci_1, (io) => {
		try {
			config_loader.load(io);
			assert(false, "Should have failed due to zero mappings");
		} catch (e) {
			assert(index(e, "CONFIG_ERROR: No valid user mappings") != -1);
		}
	});

	// Case 2: Only invalid user sections (user not in RPCD)
	let mock_uci_2 = {
		"rpcd": { "s1": { ".type": "login", "username": "real" } },
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r" },
			"u1": { ".type": "user", "rpcd_user": "fake", "rpcd_password": "p", "email": "a@b.com" }
		}
	};
	mocked.with_uci(mock_uci_2, (io) => {
		try {
			config_loader.load(io);
			assert(false, "Should have failed because all mappings were ignored");
		} catch (e) {
			assert(index(e, "CONFIG_ERROR: No valid user mappings") != -1);
		}
	});
});

test('config: logic - handle disabled state', () => {
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

test('config: logic - handle missing config', () => {
	let mocked = mock.create();
	mocked.with_uci({}, (io) => {
		assert_throws(() => config_loader.load(io));
	});
});

test('config: logic - reject missing issuer URL', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r" }
		}
	};
	mocked.with_uci(mock_uci, (io) => {
		assert_throws(() => config_loader.load(io));
	});
});

test('config: logic - reject missing clock tolerance', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r" }
		}
	};
	mocked.with_uci(mock_uci, (io) => {
		assert_throws(() => config_loader.load(io));
	});
});

test('config: logic - reject missing mandatory OIDC fields', () => {
	let mocked = mock.create();
	
	// 1. Missing client_id
	let mock_uci_1 = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_secret": "s", "redirect_uri": "https://r" }
		}
	};
	mocked.with_uci(mock_uci_1, (io) => {
		assert_throws(() => config_loader.load(io));
	});

	// 2. Missing client_secret
	let mock_uci_2 = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "redirect_uri": "https://r" }
		}
	};
	mocked.with_uci(mock_uci_2, (io) => {
		assert_throws(() => config_loader.load(io));
	});
});

test('config: logic - reject insecure redirect URI', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { 
				".type": "oidc", 
				"enabled": "1", 
				"issuer_url": "https://idp.com", 
				"clock_tolerance": "300", 
				"client_id": "c", 
				"client_secret": "s",
				"redirect_uri": "http://insecure.com/callback"
			}
		}
	};
	mocked.with_uci(mock_uci, (io) => {
		assert_throws(() => config_loader.load(io));
	});
});
