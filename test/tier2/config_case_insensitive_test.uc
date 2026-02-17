import { test, assert, assert_eq } from 'testing';
import * as config from 'luci_sso.config';

test('config: find_roles_for_user - case-insensitive email matching', () => {
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

    // User email with different casing
    let claims = {
        email: "Admin@Example.Com"
    };

    let perms = config.find_roles_for_user(mock_config, claims);
    
    // CURRENT behavior (VULNERABLE/INFLEXIBLE): Returns null role_name and empty perms.
    // EXPECTED behavior: Should match "admin_role" and return "*" permissions.
    assert_eq(perms.role_name, "admin_role", "Should match role regardless of email casing");
    assert(length(perms.read) > 0, "Should have read permissions");
});
