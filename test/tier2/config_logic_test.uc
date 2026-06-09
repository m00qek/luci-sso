import { it, assert, truthy, falsy, mock } from 'utest';
import * as config_loader from 'luci_sso.config';
import * as Result from 'luci_sso.result';

it('config: logic - successful load', () => {
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

	mock.inject('uci', { data: mock_uci }, (uci) => {
		let res = config_loader.load({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res), "Should return Result object");
		assert.match(truthy(), res.ok, "Should return successful result");
		let config = res.data;
		assert.match("https://idp.com", config.issuer_url);
		assert.match(300, config.clock_tolerance);
		assert.match("r1", config.roles[0].name);
	});
});

it('config: logic - normalization (email list vs string)', () => {
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
			"r1": { ".type": "role", "email": "single@test.com", "read": ["*"], "write": [] },
			"r2": { ".type": "role", "email": ["a@b.com", "c@d.com"], "read": ["*"], "write": [] }
		}
	};

	mock.inject('uci', { data: mock_uci }, (uci) => {
		let res = config_loader.load({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(truthy(), res.ok, "Should be ok");
		let config = res.data;
		assert.match("array", type(config.roles[0].emails), "Single email should be wrapped in array");
		assert.match(2, length(config.roles[1].emails), "Multiple emails should remain an array");
	});
});

it('config: logic - HTTPS enforcement', () => {
	let check = (url) => {
		let mock_uci = {
			"luci-sso": {
				"default": { ".type": "oidc", "enabled": "1", "issuer_url": url, "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" },
				"r1": { ".type": "role", "email": "a@b.com", "read": ["*"], "write": [] }
			}
		};
		let result = null;
		mock.inject('uci', { data: mock_uci }, (uci) => {
			let res = config_loader.load({ uci: uci.cursor(), log: () => null });
			assert.match(truthy(), Result.is(res));
			result = res.ok;
		});
		return result;
	};

	assert.match(truthy(), check("https://idp.com"), "HTTPS should be allowed");
	assert.match(falsy(), check("http://idp.com"), "Insecure remote HTTP must be rejected");
});

it('config: logic - reject empty or invalid roles', () => {
	let mock_uci_1 = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r/callback" }
		}
	};
	mock.inject('uci', { data: mock_uci_1 }, (uci) => {
		let res = config_loader.load({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(falsy(), res.ok, "Should have failed due to zero roles");
		assert.match("CONFIG_ERROR", res.error);
		assert.match(truthy(), index(res.details, "No valid roles") != -1);
	});
});

it('config: logic - handle disabled state', () => {
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "0" }
		}
	};
	mock.inject('uci', { data: mock_uci }, (uci) => {
		let res = config_loader.load({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(falsy(), res.ok);
		assert.match("SSO_DISABLED", res.error);
	});
});

it('config: logic - handle missing config', () => {
	mock.inject('uci', { data: {} }, (uci) => {
		let res = config_loader.load({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(falsy(), res.ok);
		assert.match("SSO_DISABLED", res.error); // is_enabled returns false if missing
	});
});

it('config: logic - is_enabled reflects UCI state', () => {
	// Enabled
	let uci_enabled = {
		"luci-sso": {
			"default": { ".type": "oidc", enabled: "1" }
		}
	};
	mock.inject('uci', { data: uci_enabled }, (uci) => {
		let res = config_loader.is_enabled({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(true, res.ok && res.data, "Should be enabled");
	});

	// Disabled
	let uci_disabled = {
		"luci-sso": {
			"default": { ".type": "oidc", enabled: "0" }
		}
	};
	mock.inject('uci', { data: uci_disabled }, (uci) => {
		let res = config_loader.is_enabled({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(false, res.ok && res.data, "Should be disabled");
	});

	// Missing section
	mock.inject('uci', { data: {} }, (uci) => {
		let res = config_loader.is_enabled({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(false, res.ok && res.data, "Should be disabled if missing");
	});
});

it('config: logic - reject missing issuer URL', () => {
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "clock_tolerance": "300", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r" }
		}
	};
	mock.inject('uci', { data: mock_uci }, (uci) => {
		let res = config_loader.load({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(falsy(), res.ok);
		assert.match("CONFIG_ERROR", res.error);
	});
});

it('config: logic - reject missing clock tolerance', () => {
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "client_id": "c", "client_secret": "s", "redirect_uri": "https://r" }
		}
	};
	mock.inject('uci', { data: mock_uci }, (uci) => {
		let res = config_loader.load({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(falsy(), res.ok);
		assert.match("CONFIG_ERROR", res.error);
	});
});

it('config: logic - reject missing mandatory OIDC fields', () => {
	// 1. Missing client_id
	let mock_uci_1 = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_secret": "s", "redirect_uri": "https://r" }
		}
	};
	mock.inject('uci', { data: mock_uci_1 }, (uci) => {
		let res = config_loader.load({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(falsy(), res.ok);
		assert.match("CONFIG_ERROR", res.error);
	});

	// 2. Missing client_secret
	let mock_uci_2 = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "1", "issuer_url": "https://idp.com", "clock_tolerance": "300", "client_id": "c", "redirect_uri": "https://r" }
		}
	};
	mock.inject('uci', { data: mock_uci_2 }, (uci) => {
		let res = config_loader.load({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(falsy(), res.ok);
		assert.match("CONFIG_ERROR", res.error);
	});
});

it('config: logic - reject insecure redirect URI', () => {
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
	mock.inject('uci', { data: mock_uci }, (uci) => {
		let res = config_loader.load({ uci: uci.cursor(), log: () => null });
		assert.match(truthy(), Result.is(res));
		assert.match(falsy(), res.ok);
		assert.match("CONFIG_ERROR", res.error);
	});
});
