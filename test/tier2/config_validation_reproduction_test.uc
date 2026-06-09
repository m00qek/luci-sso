'use strict';

import { it, assert, truthy, falsy, mock } from 'utest';
import * as config_loader from 'luci_sso.config';

it('config: logic - reproduction - reject internal_issuer_url with insecure scheme (W3)', () => {
	let mock_uci = {
		"luci-sso": {
			"default": {
				".type": "oidc",
				"enabled": "1",
				"issuer_url": "https://idp.com",
				"internal_issuer_url": "http://10.0.0.5", // INSECURE
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
		assert.match(falsy(), res.ok, "Should reject insecure internal_issuer_url");
		assert.match("CONFIG_ERROR", res.error);
		assert.match(truthy(), index(res.details, "internal_issuer_url must use HTTPS") >= 0, "Error message must match");
	});
});

it('config: validation - clock_tolerance range checks (N4/N5)', () => {
	let base_uci = {
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
			"r1": { ".type": "role", "email": "a@b.com", "read": ["*"], "write": ["*"] }
		}
	};

	let check = (val) => {
		let uci = { ...base_uci };
		uci["luci-sso"]["default"] = { ...uci["luci-sso"]["default"], "clock_tolerance": val };
		let result = null;
		mock.inject('uci', { data: uci }, (proxy) => {
			result = config_loader.load({ uci: proxy.cursor(), log: () => null });
		});
		return result;
	};

	// Happy path
	assert.match(truthy(), check("0").ok);
	assert.match(truthy(), check("3600").ok);
	assert.match(truthy(), check("60").ok);

	// Error paths
	let res_neg = check("-1");
	assert.match(falsy(), res_neg.ok);
	assert.match("CONFIG_ERROR", res_neg.error);
	assert.match(truthy(), index(res_neg.details, "between 0 and 3600") != -1);

	let res_large = check("3601");
	assert.match(falsy(), res_large.ok);
	assert.match("CONFIG_ERROR", res_large.error);

	let res_invalid = check("abc");
	assert.match(falsy(), res_invalid.ok);
	assert.match("CONFIG_ERROR", res_invalid.error);
});
