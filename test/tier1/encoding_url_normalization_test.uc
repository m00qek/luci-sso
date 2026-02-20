import { test, assert_eq } from 'testing';
import { normalize_url } from 'luci_sso.encoding';

test('encoding: normalize_url - preserves path case while lowercasing origin', () => {
    assert_eq(normalize_url("HTTPS://IDP.COM/Realms/MyOrg"), "https://idp.com/Realms/MyOrg", "Should lowercase scheme and host, but NOT path");
    assert_eq(normalize_url("https://idp.lan:8443/Path/To/Resource/"), "https://idp.lan:8443/Path/To/Resource", "Should remove trailing slash and preserve path case");
    assert_eq(normalize_url("https://idp.com"), "https://idp.com", "Should handle origin-only URL");
    assert_eq(normalize_url("HTTPS://IDP.COM/"), "https://idp.com", "Should handle origin-only URL with trailing slash");
    assert_eq(normalize_url("https://idp.com///"), "https://idp.com", "Should handle multiple trailing slashes");
    assert_eq(normalize_url("invalid-url"), "invalid-url", "Should return original if it doesn't match standard OIDC URL pattern");
});
