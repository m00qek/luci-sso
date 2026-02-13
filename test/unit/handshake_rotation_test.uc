import { test, assert, assert_eq } from '../testing.uc';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';
import * as h from 'unit.helpers';

test('handshake: recovery - handle JWKS key rotation with automatic retry', () => {
    let access_token = "access-token-123";
    let secret = f.MOCK_CONFIG.client_secret;
    
    // Ensure config is fully populated as config.load() would do
    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: f.MOCK_CONFIG.issuer_url,
        redirect_uri: "https://r/c",
        roles: [
            { name: "r1", emails: ["user-123"], read: ["*"], write: ["*"] }
        ]
    };

    // 2. Setup stateful mock responses
    let jwks_uri = f.MOCK_DISCOVERY.jwks_uri;
    let old_jwks = { keys: [ f.MOCK_JWK ] };
    let new_jwks = { keys: [ f.ROTATION_NEW_JWK ] }; 

    let call_count = 0;
    
    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_uci({
            "luci-sso": {
                "default": { ...test_config, ".type": "oidc", "enabled": "1" },
                "r1": { ".type": "role", "email": ["user-123"], "read": ["*"], "write": ["*"] }
            }
        })
        .with_ubus({
            "session:create": { "ubus_rpc_session": "s123" },
            "session:grant": {},
            "session:set": {}
        })
        .spy((io) => {
            io.http_get = (url) => {
                let data = null;
                if (url == f.MOCK_DISCOVERY.issuer + "/.well-known/openid-configuration") {
                    data = f.MOCK_DISCOVERY;
                } else if (url == jwks_uri) {
                    call_count++;
                    data = (call_count == 1) ? old_jwks : new_jwks;
                }
                if (data) return { status: 200, body: { read: () => sprintf("%J", data) } };
                return { status: 404, body: { read: () => "" } };
            };

            // Create a valid handshake state
            let state_res = session.create_state(io);
            if (!state_res.ok) {
                print("create_state failed: " + state_res.error + " " + (state_res.details || ""));
                assert(false);
            }
            let s_data = state_res.data;

            // Create ID token matching the generated nonce
            let payload = { 
                ...f.MOCK_CLAIMS,
                email: "user-123",
                nonce: s_data.nonce,
                at_hash: crypto.b64url_encode(substr(crypto.sha256(access_token), 0, 16))
            };
            payload.kid = f.ROTATION_NEW_JWK.kid;
            let token = h.generate_id_token(payload, f.ROTATION_NEW_PRIVKEY, "RS256");
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

            // This should trigger the rotation recovery path
            let res = handshake.authenticate(io, test_config, request);
            
            assert(res.ok, `Handshake should succeed after JWKS retry (Error: ${res.error}, Details: ${res.details})`);
            assert_eq(call_count, 2, "JWKS should have been fetched exactly twice (initial + forced refresh)");
        });
});