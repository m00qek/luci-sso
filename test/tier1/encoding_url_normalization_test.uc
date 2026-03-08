import { test, assert, assert_eq } from 'testing';
import { normalize_url } from 'luci_sso.encoding';

test('encoding: normalize_url - preserves path case while lowercasing origin', () => {
    assert_eq(normalize_url("HTTPS://IDP.COM/Realms/MyOrg").data, "https://idp.com/Realms/MyOrg", "Should lowercase scheme and host, but NOT path");
    assert_eq(normalize_url("https://idp.lan:8443/Path/To/Resource/").data, "https://idp.lan:8443/Path/To/Resource", "Should remove trailing slash and preserve path case");
    assert_eq(normalize_url("https://idp.com").data, "https://idp.com", "Should handle origin-only URL");
    assert_eq(normalize_url("HTTPS://IDP.COM/").data, "https://idp.com", "Should handle origin-only URL with trailing slash");
    assert_eq(normalize_url("https://idp.com///").data, "https://idp.com", "Should handle multiple trailing slashes");
    
    let res = normalize_url("invalid-url");
    assert(!res.ok, "Should fail for invalid URL format");
    assert_eq(res.error, "MALFORMED_URL");
});

// W2: Missing Port Normalization
test('encoding: normalize_url - W2 default port stripping regression', () => {
	// HTTPS default port 443
	assert_eq(normalize_url("https://idp.example.com:443/realms/main").data, "https://idp.example.com/realms/main", "W2: Should strip :443 for HTTPS");
	assert_eq(normalize_url("HTTPS://idp.example.com:443").data, "https://idp.example.com", "W2: Should strip :443 for HTTPS (no path)");
	
	// HTTP default port 80
	assert_eq(normalize_url("http://idp.example.com:80/realms/main").data, "http://idp.example.com/realms/main", "W2: Should strip :80 for HTTP");
	assert_eq(normalize_url("HTTP://idp.example.com:80").data, "http://idp.example.com", "W2: Should strip :80 for HTTP (no path)");

	// Non-default ports SHOULD remain
	assert_eq(normalize_url("https://idp.example.com:8443/realms/main").data, "https://idp.example.com:8443/realms/main", "Should NOT strip non-default port :8443");
	assert_eq(normalize_url("http://idp.example.com:8080").data, "http://idp.example.com:8080", "Should NOT strip non-default port :8080");

    // Host with '443' or '80' as part of name (not port) should be safe
    assert_eq(normalize_url("https://idp443.com/").data, "https://idp443.com", "Should NOT strip 443 if it is part of hostname");
});
