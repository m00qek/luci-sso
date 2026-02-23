import { test, assert, assert_eq } from 'testing';
import * as handshake from 'luci_sso.handshake';
import * as mock from 'mock';

test('handshake: groups fallback - reproduction of dead code', () => {
    let factory = mock.create();

    // ID Token with no groups
    let id_token_payload = {
        iss: "https://idp.com",
        sub: "user123",
        aud: "client123",
        exp: 2000000000,
        iat: 1000000000,
        nonce: "nonce123"
    };

    // UserInfo WITH groups
    let userinfo_payload = {
        sub: "user123",
        groups: ["admin", "users"]
    };

    factory.with_responses({
        "https://idp.com/token": {
            status: 200,
            body: sprintf('{"access_token":"at","id_token":"it","token_type":"Bearer"}')
        },
        "https://idp.com/userinfo": {
            status: 200,
            body: sprintf('%J', userinfo_payload)
        }
    }).with_files({
        "/tmp/luci-sso/handshake_h1.json": sprintf('%J', {
            id: "h1",
            state: "s1",
            nonce: "nonce123",
            code_verifier: "v1",
            iat: 1000000000,
            exp: 2000000000
        })
    }).spy((io) => {
        // Mock OIDC and crypto to bypass JWT validation complexity for this logic test
        // We want to see if handshake.authenticate correctly merges groups
        
        // This is a Tier 2 test, so we rely on the internal logic of _complete_oauth_flow
        // which calls oidc.fetch_userinfo and then attempts the merge.
    });

    // Since _complete_oauth_flow is private, we test through authenticate or verify the specific logic block
});
