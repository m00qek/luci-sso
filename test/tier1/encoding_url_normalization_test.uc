import { it, assert, truthy, falsy } from 'utest';
import { normalize_url } from 'luci_sso.encoding';

it('encoding: normalize_url - preserves path case while lowercasing origin', () => {
    assert.match("https://idp.com/Realms/MyOrg", normalize_url("HTTPS://IDP.COM/Realms/MyOrg").data, "Should lowercase scheme and host, but NOT path");
    assert.match("https://idp.lan:8443/Path/To/Resource", normalize_url("https://idp.lan:8443/Path/To/Resource/").data, "Should remove trailing slash and preserve path case");
    assert.match("https://idp.com", normalize_url("https://idp.com").data, "Should handle origin-only URL");
    assert.match("https://idp.com", normalize_url("HTTPS://IDP.COM/").data, "Should handle origin-only URL with trailing slash");
    assert.match("https://idp.com", normalize_url("https://idp.com///").data, "Should handle multiple trailing slashes");
    
    let res = normalize_url("invalid-url");
    assert.match(falsy(), res.ok, "Should fail for invalid URL format");
    assert.match("MALFORMED_URL", res.error);
});

// W2: Missing Port Normalization
it('encoding: normalize_url - W2 default port stripping regression', () => {
	// HTTPS default port 443
	assert.match("https://idp.example.com/realms/main", normalize_url("https://idp.example.com:443/realms/main").data, "W2: Should strip :443 for HTTPS");
	assert.match("https://idp.example.com", normalize_url("HTTPS://idp.example.com:443").data, "W2: Should strip :443 for HTTPS (no path)");
	
	// HTTP default port 80
	assert.match("http://idp.example.com/realms/main", normalize_url("http://idp.example.com:80/realms/main").data, "W2: Should strip :80 for HTTP");
	assert.match("http://idp.example.com", normalize_url("HTTP://idp.example.com:80").data, "W2: Should strip :80 for HTTP (no path)");

	// Non-default ports SHOULD remain
	assert.match("https://idp.example.com:8443/realms/main", normalize_url("https://idp.example.com:8443/realms/main").data, "Should NOT strip non-default port :8443");
	assert.match("http://idp.example.com:8080", normalize_url("http://idp.example.com:8080").data, "Should NOT strip non-default port :8080");

    // Host with '443' or '80' as part of name (not port) should be safe
    assert.match("https://idp443.com", normalize_url("https://idp443.com/").data, "Should NOT strip 443 if it is part of hostname");
});
