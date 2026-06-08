import { it, assert, truthy } from 'utest';
import * as config_loader from 'luci_sso.config';
import * as Result from 'luci_sso.result';
import * as mock from 'mock';

it('config: logic - HTTPS protocol case-insensitivity (RFC 3986)', () => {
	let mocked = mock.create();

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

		return mocked.with_uci(mock_uci, (io) => {
			let res = config_loader.load(io);
			assert.match(truthy(), Result.is(res), "Should return Result object");
			return res.ok;
		});
	};

	// Standard lowercase (should pass)
	assert.match(truthy(), check("https://idp.com", "https://app.com/callback", "https://internal-idp.com"), "Standard lowercase HTTPS should pass");

	// Uppercase scheme (should pass per RFC 3986, but currently FAILS)
	assert.match(truthy(), check("HTTPS://idp.com", "https://app.com/callback"), "Uppercase issuer HTTPS:// should pass");
	assert.match(truthy(), check("https://idp.com", "HTTPS://app.com/callback"), "Uppercase redirect HTTPS:// should pass");
	assert.match(truthy(), check("https://idp.com", "https://app.com/callback", "HTTPS://internal-idp.com"), "Uppercase internal_issuer_url HTTPS:// should pass");

	// Mixed case scheme (should pass)
	assert.match(truthy(), check("hTTpS://idp.com", "https://app.com/callback"), "Mixed case hTTpS:// should pass");
});
