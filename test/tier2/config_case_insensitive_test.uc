import { describe, it, assert, truthy } from 'utest';
import * as config from 'luci_sso.config';

describe('config: find_roles_for_user', () => {
	it('case-insensitive email matching', () => {
		let mock_config = {
			roles: [
				{
					name: "admin_role",
					emails: ["admin@example.com"],
					read: ["*"],
					write: ["*"]
				}
			]
		};

		let claims = {
			email: "Admin@Example.Com"
		};

		let res = config.find_roles_for_user(mock_config, claims);
		assert.match(truthy(), res.ok, "Should succeed in matching role");

		let perms = res.data;
		assert.match("admin_role", perms.role_name, "Should match role regardless of email casing");
		assert.match(truthy(), length(perms.read) > 0, "Should have read permissions");
	});
});
