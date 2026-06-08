import { it, assert, truthy, falsy } from 'utest';
import * as oidc from 'luci_sso.oidc';

it('oidc: get_auth_url - rejects fragments in authorization_endpoint (W2)', () => {
    let mock_config = {
        client_id: "client123",
        redirect_uri: "https://r/c",
        scope: "openid profile email"
    };

    // RFC 6749 §3.1: "The endpoint URI MUST NOT include a fragment component."
    let discovery_doc = {
        authorization_endpoint: "https://idp.com/auth#fragment"
    };

    let params = {
        state: "1234567890123456",
        nonce: "1234567890123456",
        code_challenge: "challenge"
    };

    let res = oidc.get_auth_url({}, mock_config, discovery_doc, params);
    
    assert.match(falsy(), res.ok, "Authorization endpoint with fragment MUST be rejected");
    assert.match("INVALID_AUTH_ENDPOINT", res.error);
});
