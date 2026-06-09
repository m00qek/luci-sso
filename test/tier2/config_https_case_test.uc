import { it, assert, truthy, mock } from 'utest';
import * as config_loader from 'luci_sso.config';
import * as Result from 'luci_sso.result';

it('config: logic - HTTPS protocol case-insensitivity (RFC 3986)', () => {
	let check = (url, redirect, internal) => {
		let mock_uci = {
			"luci-sso": {
				"default": {
					".type": "oidc",
					"enabled": "1",
					"issuer_url": url,
					"client_id": "c1",
					"client_secret": "s1",
					"redirect_uri": redirect,
					"clock_tolerance": "300",
					"internal_issuer_url": internal
				},
				"r1": { ".type": "role", "email": "admin@test.com", "read": ["*"], "write": ["*"] }
			}
		};

		let result = null;
		mock.inject('uci', { data: mock_uci }, (uci) => {
			let res = config_loader.load({ uci: uci.cursor(), log: () => null });
			assert.match(truthy(), Result.is(res), "Should return Result object");
			result = res.ok;
		});
		return result;
	};

	assert.match(truthy(), check("https://idp.com", "https://app.com/callback", "https://internal-idp.com"), "Standard lowercase HTTPS should pass");
	assert.match(truthy(), check("HTTPS://idp.com", "https://app.com/callback"), "Uppercase issuer HTTPS:// should pass");
	assert.match(truthy(), check("https://idp.com", "HTTPS://app.com/callback"), "Uppercase redirect HTTPS:// should pass");
	assert.match(truthy(), check("https://idp.com", "https://app.com/callback", "HTTPS://internal-idp.com"), "Uppercase internal_issuer_url HTTPS:// should pass");
	assert.match(truthy(), check("hTTpS://idp.com", "https://app.com/callback"), "Mixed case hTTpS:// should pass");
});
