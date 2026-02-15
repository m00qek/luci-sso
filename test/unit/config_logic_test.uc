import { test, assert, assert_eq, assert_throws } from 'testing';
import * as config_loader from 'luci_sso.config';
import * as Result from 'luci_sso.result';
import * as mock from 'mock';

// =============================================================================
// Tier 2: Configuration Logic (Platinum Suite)
// =============================================================================

test('config: logic - successful load', () => {
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
                        "r1": { ".type": "role", "email": "admin@test.com", "read": ["*"], "write": ["*"] }
                }
        };

        mocked.with_uci(mock_uci, (io) => {
                let res = config_loader.load(io);
                assert(Result.is(res), "Should return Result object");
                assert(res.ok, "Should return successful result");
                let config = res.data;
                assert_eq(config.issuer_url, "https://idp.com");
                assert_eq(config.clock_tolerance, 300);
                assert_eq(config.roles[0].name, "r1");
        });
});

test('config: logic - normalization (email list vs string)', () => {
        let mocked = mock.create();
        let mock_uci = {
                "luci-sso": {
                        "default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
                        "r1": { ".type": "role", "email": "single@test.com", "read": ["*"], "write": [] },
                        "r2": { ".type": "role", "email": ["a@b.com", "c@d.com"], "read": ["*"], "write": [] }
                }
        };

        mocked.with_uci(mock_uci, (io) => {
                let res = config_loader.load(io);
                assert(Result.is(res));
                assert(res.ok, "Should be ok");
                let config = res.data;
                assert_eq(type(config.roles[0].emails), "array", "Single email should be wrapped in array");
                assert_eq(length(config.roles[1].emails), 2, "Multiple emails should remain an array");
        });
});

test('config: logic - HTTPS enforcement', () => {
        let mocked = mock.create();

        let check = (url) => {
                let mock_uci = {
                        "luci-sso": { 
                                "default": { ".type": "oidc", "enabled": "1", "issuer_url": url, "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
                                "r1": { ".type": "role", "email": "a@b.com", "read": ["*"], "write": [] }
                        }
                };
                return mocked.with_uci(mock_uci, (io) => {
                        let res = config_loader.load(io);
                        assert(Result.is(res));
                        return res.ok;
                });
        };

        assert(check("https://idp.com"), "HTTPS should be allowed");
        assert(!check("http://idp.com"), "Insecure remote HTTP must be rejected");
});

test('config: logic - reject empty or invalid roles', () => {
        let mocked = mock.create();

        // Case 1: No role sections at all
        let mock_uci_1 = {
                "luci-sso": {
                        "default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" }
                }
        };
        mocked.with_uci(mock_uci_1, (io) => {
                let res = config_loader.load(io);
                assert(Result.is(res));
                assert(!res.ok, "Should have failed due to zero roles");
                assert_eq(res.error, "CONFIG_ERROR");
                assert(index(res.details, "No valid roles") != -1);
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
		let res = config_loader.load(io);
                assert(Result.is(res));
                assert(!res.ok);
                assert_eq(res.error, "DISABLED");
	});
});

test('config: logic - handle missing config', () => {
	let mocked = mock.create();
	mocked.with_uci({}, (io) => {
		let res = config_loader.load(io);
                assert(Result.is(res));
                assert(!res.ok);
                assert_eq(res.error, "DISABLED"); // is_enabled returns false if missing
	});
});

test('config: logic - is_enabled reflects UCI state', () => {
	let factory = mock.create();
	
	// Enabled
	let uci_enabled = {
		"luci-sso": {
			"default": { ".type": "oidc", enabled: "1" }
		}
	};
	factory.with_uci(uci_enabled, (io) => {
		assert(config_loader.is_enabled(io), "Should be enabled");
	});

	// Disabled
	let uci_disabled = {
		"luci-sso": {
			"default": { ".type": "oidc", enabled: "0" }
		}
	};
	factory.with_uci(uci_disabled, (io) => {
		assert(!config_loader.is_enabled(io), "Should be disabled");
	});

	// Missing section
	factory.with_uci({}, (io) => {
		assert(!config_loader.is_enabled(io), "Should be disabled if missing");
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
		let res = config_loader.load(io);
                assert(Result.is(res));
                assert(!res.ok);
                assert_eq(res.error, "CONFIG_ERROR");
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
		let res = config_loader.load(io);
                assert(Result.is(res));
                assert(!res.ok);
                assert_eq(res.error, "CONFIG_ERROR");
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
		let res = config_loader.load(io);
                assert(Result.is(res));
                assert(!res.ok);
                assert_eq(res.error, "CONFIG_ERROR");
	});

	// 2. Missing client_secret
	let mock_uci_2 = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "redirect_uri": "https://r" }
		}
	};
	mocked.with_uci(mock_uci_2, (io) => {
		let res = config_loader.load(io);
                assert(Result.is(res));
                assert(!res.ok);
                assert_eq(res.error, "CONFIG_ERROR");
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
		let res = config_loader.load(io);
                assert(Result.is(res));
                assert(!res.ok);
                assert_eq(res.error, "CONFIG_ERROR");
	});
});
