import { test, assert, assert_eq } from 'testing';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

test('handshake: security - DO NOT retry JWKS refresh if kid is missing', () => {
    let access_token = "access-token-123";
    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: f.MOCK_CONFIG.issuer_url,
        redirect_uri: "https://r/c",
    };

    let jwks_uri = f.MOCK_DISCOVERY.jwks_uri;
    let jwks = { keys: [ f.MOCK_JWK ] };

    let call_count = 0;
    
    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_uci({
            "luci-sso": {
                "default": { ...test_config, ".type": "oidc", "enabled": "1" }
            }
        })
        .spy((io) => {
            io.http_get = (url) => {
                if (url == f.MOCK_DISCOVERY.issuer + "/.well-known/openid-configuration") {
                    return { status: 200, body: { read: () => sprintf("%J", f.MOCK_DISCOVERY) } };
                } else if (url == jwks_uri) {
                    call_count++;
                    return { status: 200, body: { read: () => sprintf("%J", jwks) } };
                }
                return { status: 404, body: { read: () => "" } };
            };

            // Create a valid handshake state
            let state_res = session.create_state(io);
            assert(state_res.ok);
            let s_data = state_res.data;

            // Create ID token WITHOUT kid
            let payload = { 
                ...f.MOCK_CLAIMS,
                nonce: s_data.nonce
            };
            // Generate token with a different key to ensure signature failure
            let token = h.generate_id_token(payload, f.ROTATION_NEW_PRIVKEY, "RS256", null); // Passing null for kid
            let tokens = { access_token: access_token, id_token: token };

            io.http_post = (url) => ({ 
                status: 200, 
                body: { read: () => sprintf("%J", tokens) } 
            });

            let request = {
                path: "/callback",
                query: { code: "c1", state: s_data.state },
                cookies: { "__Host-luci_sso_state": s_data.token },
                env: { HTTPS: "on" }
            };

            // This should NOT trigger the rotation recovery path because kid is missing
            let res = handshake.authenticate(io, test_config, request);
            
            assert(!res.ok, "Handshake should fail due to invalid signature");
            assert_eq(res.error, "ID_TOKEN_VERIFICATION_FAILED");
            assert_eq(res.details?.details, "INVALID_SIGNATURE");
            assert_eq(call_count, 1, "JWKS should have been fetched exactly once (no retry should occur if kid is missing)");
        });
});
