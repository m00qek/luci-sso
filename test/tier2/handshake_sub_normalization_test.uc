import { test, assert, assert_eq } from 'testing';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

const TEST_POLICY = { allowed_algs: ["RS256", "ES256"] };

test('REPRODUCTION: handshake: userinfo fallback fails on case-mismatched sub', () => {
    let issuer_url = f.MOCK_CONFIG.issuer_url;
    let discovery_doc = {
        ...f.MOCK_DISCOVERY,
        authorization_endpoint: "https://trusted.idp/auth",
        token_endpoint: "https://trusted.idp/token",
        jwks_uri: "https://trusted.idp/jwks",
        userinfo_endpoint: "https://trusted.idp/userinfo"
    };

    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: "https://trusted.idp",
        roles: [ { name: "admin", emails: ["user@example.com"], read: ["*"], write: ["*"] } ]
    };

    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_ubus({ "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} })
        .with_responses({
            [issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
            [discovery_doc.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
            // UserInfo returns UPPERCASE sub
            [discovery_doc.userinfo_endpoint]: { status: 200, body: { sub: "USER-123", email: "user@example.com" } }
        })
        .spy((io) => {
            let captured_nonce = null;
            let original_write_file = io.write_file;
            io.write_file = (path, data) => {
                if (match(path, /handshake_.*\.json/)) {
                    let res = crypto.safe_json(data);
                    if (res.ok) captured_nonce = res.data.nonce;
                }
                return original_write_file(path, data);
            };

            io.http_post = (url, opts) => {
                let access_token = "at-123";
                // ID Token has lowercase sub
                let payload = { 
                    ...f.MOCK_CLAIMS, 
                    sub: "user-123",
                    email: null, 
                    nonce: captured_nonce, 
                    at_hash: crypto.b64url_encode(substr(crypto.sha256(access_token), 0, 16)) 
                };
                let token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
                return { status: 200, body: { read: () => sprintf("%J", { access_token: access_token, id_token: token }) } };
            };

            let s_res = handshake.initiate(io, test_config);
            let s_data = s_res.data;
            let token = s_data.token;
            let state_in_url = split(s_data.url, "state=")[1];
            state_in_url = split(state_in_url, "&")[0];

            let request = {
                query: { code: "c123", state: state_in_url },
                cookies: { "__Host-luci_sso_state": token }
            };

            let res = handshake.authenticate(io, test_config, request, TEST_POLICY);
            
            // Expected: SUCCESS because of normalization
            assert(res.ok, "Should SUCCEED after sub normalization fix");
            assert_eq(res.data.email, "user@example.com");
        });
});
