import { it, assert, truthy } from 'utest';
import * as config_loader from 'luci_sso.config';
import * as Result from 'luci_sso.result';
import * as mock from 'mock';

// =============================================================================
// Tier 2: Configuration Logic (Platinum Suite)
// =============================================================================

it('config: logic - successful load', () => {
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
                assert.match(truthy(), Result.is(res), "Should return Result object");
                assert.match(truthy(), res.ok, "Should return successful result");
                let config = res.data;
                assert.match("https://idp.com", config.issuer_url);
                assert.match(300, config.clock_tolerance);
                assert.match("r1", config.roles[0].name);
        });
});

it('config: logic - normalization (email list vs string)', () => {
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
                assert.match(truthy(), Result.is(res));
                assert.match(truthy(), res.ok, "Should be ok");
                let config = res.data;
                assert.match("array", type(config.roles[0].emails), "Single email should be wrapped in array");
                assert.match(2, length(config.roles[1].emails), "Multiple emails should remain an array");
        });
});

it('config: logic - HTTPS enforcement', () => {
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
                        assert.match(truthy(), Result.is(res));
                        return res.ok;
                });
        };

        assert.match(truthy(), check("https://idp.com"), "HTTPS should be allowed");
        assert.match(truthy(), !check("http://idp.com"), "Insecure remote HTTP must be rejected");
});

it('config: logic - reject empty or invalid roles', () => {
        let mocked = mock.create();

        // Case 1: No role sections at all
        let mock_uci_1 = {
                "luci-sso": {
                        "default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" }
                }
        };
        mocked.with_uci(mock_uci_1, (io) => {
                let res = config_loader.load(io);
                assert.match(truthy(), Result.is(res));
                assert.match(truthy(), !res.ok, "Should have failed due to zero roles");
                assert.match("CONFIG_ERROR", res.error);
                assert.match(truthy(), index(res.details, "No valid roles") != -1);
        });
});
it('config: logic - handle disabled state', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "0" }
		}
	};
	mocked.with_uci(mock_uci, (io) => {
		let res = config_loader.load(io);
                assert.match(truthy(), Result.is(res));
                assert.match(truthy(), !res.ok);
                assert.match("SSO_DISABLED", res.error);
	});
});

it('config: logic - handle missing config', () => {
	let mocked = mock.create();
	mocked.with_uci({}, (io) => {
		let res = config_loader.load(io);
                assert.match(truthy(), Result.is(res));
                assert.match(truthy(), !res.ok);
                assert.match("SSO_DISABLED", res.error); // is_enabled returns false if missing
	});
});

it('config: logic - is_enabled reflects UCI state', () => {
	let factory = mock.create();
	
	// Enabled
	let uci_enabled = {
		"luci-sso": {
			"default": { ".type": "oidc", enabled: "1" }
		}
	};
	factory.with_uci(uci_enabled, (io) => {
		let res = config_loader.is_enabled(io);
		assert.match(truthy(), Result.is(res));
		assert.match(truthy(), res.ok && res.data === true, "Should be enabled");
	});

	// Disabled
	let uci_disabled = {
		"luci-sso": {
			"default": { ".type": "oidc", enabled: "0" }
		}
	};
	factory.with_uci(uci_disabled, (io) => {
		let res = config_loader.is_enabled(io);
		assert.match(truthy(), Result.is(res));
		assert.match(truthy(), res.ok && res.data === false, "Should be disabled");
	});

	// Missing section
	factory.with_uci({}, (io) => {
		let res = config_loader.is_enabled(io);
		assert.match(truthy(), Result.is(res));
		assert.match(truthy(), res.ok && res.data === false, "Should be disabled if missing");
	});
});

it('config: logic - reject missing issuer URL', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r" }
		}
	};
	mocked.with_uci(mock_uci, (io) => {
		let res = config_loader.load(io);
                assert.match(truthy(), Result.is(res));
                assert.match(truthy(), !res.ok);
                assert.match("CONFIG_ERROR", res.error);
	});
});

it('config: logic - reject missing clock tolerance', () => {
	let mocked = mock.create();
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r" }
		}
	};
	mocked.with_uci(mock_uci, (io) => {
		let res = config_loader.load(io);
                assert.match(truthy(), Result.is(res));
                assert.match(truthy(), !res.ok);
                assert.match("CONFIG_ERROR", res.error);
	});
});

it('config: logic - reject missing mandatory OIDC fields', () => {
	let mocked = mock.create();
	
	// 1. Missing client_id
	let mock_uci_1 = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_secret": "s", "redirect_uri": "https://r" }
		}
	};
	mocked.with_uci(mock_uci_1, (io) => {
		let res = config_loader.load(io);
                assert.match(truthy(), Result.is(res));
                assert.match(truthy(), !res.ok);
                assert.match("CONFIG_ERROR", res.error);
	});

	// 2. Missing client_secret
	let mock_uci_2 = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "redirect_uri": "https://r" }
		}
	};
	mocked.with_uci(mock_uci_2, (io) => {
		let res = config_loader.load(io);
                assert.match(truthy(), Result.is(res));
                assert.match(truthy(), !res.ok);
                assert.match("CONFIG_ERROR", res.error);
	});
});

it('config: logic - reject insecure redirect URI', () => {
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
                assert.match(truthy(), Result.is(res));
                assert.match(truthy(), !res.ok);
                assert.match("CONFIG_ERROR", res.error);
	});
});
