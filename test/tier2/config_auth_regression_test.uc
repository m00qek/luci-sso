import { test, assert, assert_eq } from 'testing';
import * as config_loader from 'luci_sso.config';
import * as mock from 'mock';

test('config: auth regression - deny role with empty permissions', () => {
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
				"redirect_uri": "https://r/callback" 
			},
			"r_empty": { 
				".type": "role", 
				"email": ["empty@test.com"], 
				"read": [], 
				"write": [] 
			}
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let config_res = config_loader.load(io);
		assert(config_res.ok, "Should load config");
		let config = config_res.data;

		let res = config_loader.find_roles_for_user(config, { email: "empty@test.com" });
		
		// This is expected to FAIL before the fix
		assert(!res.ok, "Should DENY user with empty permissions role");
		assert_eq(res.error, "NO_ROLES_MATCHED", "Error code should be NO_ROLES_MATCHED");
	});
});

test('config: auth regression - allow user if AT LEAST ONE matched role has permissions', () => {
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
				"redirect_uri": "https://r/callback" 
			},
			"r_empty": { 
				".type": "role", 
				"email": ["user@test.com"], 
				"read": [], 
				"write": [] 
			},
			"r_valid": { 
				".type": "role", 
				"email": ["user@test.com"], 
				"read": ["some-perm"], 
				"write": [] 
			}
		}
	};

	mocked.with_uci(mock_uci, (io) => {
		let config = config_loader.load(io).data;
		let res = config_loader.find_roles_for_user(config, { email: "user@test.com" });
		
		assert(res.ok, "Should ALLOW user if one role matches with permissions");
		assert_eq(length(res.data.read), 1);
		assert_eq(res.data.read[0], "some-perm");
	});
});
