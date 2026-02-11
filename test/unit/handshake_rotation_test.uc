import { test, assert, assert_eq } from '../testing.uc';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';

test('handshake: recovery - handle JWKS key rotation with automatic retry', () => {
    let access_token = "access-token-123";
    let secret = f.MOCK_CONFIG.client_secret;
    
    // Ensure config is fully populated as config.load() would do
    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: f.MOCK_CONFIG.issuer_url,
        redirect_uri: "https://r/c",
        user_mappings: [
            { rpcd_user: "root", rpcd_password: "p", emails: ["user-123"] }
        ]
    };

    // 2. Setup stateful mock responses
    let jwks_uri = f.MOCK_DISCOVERY.jwks_uri;
    // Keys MUST have valid Base64URL encoded 'k' for octet keys
    let old_jwks = { keys: [{ kty: "oct", kid: "key_old", k: crypto.b64url_encode("old-stale-secret-123") }] };
    let new_jwks = { keys: [{ kty: "oct", kid: "HS256", k: crypto.b64url_encode(secret) }] }; 

    let call_count = 0;
    
    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_uci({
            "luci-sso": {
                "default": { ...test_config, ".type": "oidc", "enabled": "1" },
                "user1": { ".type": "user", "rpcd_user": "root", "rpcd_password": "p", "email": ["user-123"] }
            },
            "rpcd": { "root": { ".type": "login", "username": "root" } }
        })
        .with_ubus({
            "session:login": { "ubus_rpc_session": "s123" },
            "session:set": {}
        })
        .spy((io) => {
            // Create a valid handshake state
            let state_res = session.create_state(io);
            let s_data = state_res.data;

            // Create ID token matching the generated nonce
            let payload = { 
                ...f.MOCK_CLAIMS,
                email: "user-123",
                nonce: s_data.nonce,
                at_hash: crypto.b64url_encode(substr(crypto.sha256(access_token), 0, 16))
            };
            let token = crypto.sign_jws(payload, secret);
            let tokens = { access_token: access_token, id_token: token };

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
            let res = handshake.authenticate(io, test_config, request, { allowed_algs: ["HS256"] });
            
            assert(res.ok, `Handshake should succeed after JWKS retry (Error: ${res.error}, Details: ${res.details})`);
            assert_eq(call_count, 2, "JWKS should have been fetched exactly twice (initial + forced refresh)");
        });
});