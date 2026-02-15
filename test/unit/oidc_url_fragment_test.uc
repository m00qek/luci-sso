import { test, assert, assert_eq } from '../testing.uc';
import * as oidc from 'luci_sso.oidc';

test('oidc: get_auth_url - handles fragments in authorization_endpoint correctly', () => {
    let mock_config = {
        client_id: "client123",
        redirect_uri: "https://r/c",
        scope: "openid profile email"
    };

    let discovery_doc = {
        authorization_endpoint: "https://idp.com/auth#fragment"
    };

    let params = {
        state: "1234567890123456",
        nonce: "1234567890123456",
        code_challenge: "challenge"
    };

    let res = oidc.get_auth_url({}, mock_config, discovery_doc, params);
    
    assert(res.ok);
    let url = res.data;
    
    // RFC 3986: Query MUST come BEFORE fragment.
    // CURRENT behavior (VULNERABLE): https://idp.com/auth#fragment?response_type=code...
    // EXPECTED behavior: https://idp.com/auth?response_type=code...#fragment
    
    let frag_idx = index(url, "#");
    let query_idx = index(url, "?");
    
    assert(query_idx != -1, "URL should contain a query string");
    assert(frag_idx != -1, "URL should preserve the original fragment");
    assert(query_idx < frag_idx, "Query string MUST precede the fragment (RFC 3986 §3.4)");
});
