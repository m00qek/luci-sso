'use strict';

import { test, assert, assert_eq } from 'testing';
import * as config_loader from 'luci_sso.config';
import * as mock from 'mock';

test('config: logic - reproduction - reject internal_issuer_url with insecure scheme (W3)', () => {
    let mocked = mock.create();
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

    mocked.with_uci(mock_uci, (io) => {
        let res = config_loader.load(io);
        assert(!res.ok, "Should reject insecure internal_issuer_url");
        assert_eq(res.error, "CONFIG_ERROR");
        assert(index(res.details, "internal_issuer_url must use HTTPS") >= 0, "Error message must match");
    });
});

test('config: validation - clock_tolerance range checks (N4/N5)', () => {
	let mocked = mock.create();
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
		return mocked.with_uci(uci, (io) => config_loader.load(io));
	};

	// Happy path
	assert(check("0").ok);
	assert(check("3600").ok);
	assert(check("60").ok);

	// Error paths
	let res_neg = check("-1");
	assert(!res_neg.ok);
	assert_eq(res_neg.error, "CONFIG_ERROR");
	assert(index(res_neg.details, "between 0 and 3600") != -1);

	let res_large = check("3601");
	assert(!res_large.ok);
	assert_eq(res_large.error, "CONFIG_ERROR");

	let res_invalid = check("abc");
	assert(!res_invalid.ok);
	assert_eq(res_invalid.error, "CONFIG_ERROR");
});
