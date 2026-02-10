import { test, assert, assert_eq } from '../testing.uc';
import * as handshake from 'luci_sso.handshake';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';

test('Handshake: Warning - Log warning for long-lived access tokens (W2)', () => {
    let now = 1516239022;
    // Lifetime = 25 hours (90000 seconds) > 24 hours (86400)
    let payload = { iat: now, exp: now + 90000 };
    let long_lived_token = "header." + crypto.b64url_encode(sprintf("%J", payload)) + ".signature";
    
    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: f.MOCK_CONFIG.issuer_url,
        redirect_uri: "https://r/c",
        user_mappings: [{ rpcd_user: "root", rpcd_password: "p", emails: ["user-123"] }]
    };

    let tokens = { access_token: long_lived_token, id_token: "mock.id.token" };

    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_ubus({ "session:login": { "ubus_rpc_session": "s1" }, "session:set": {} })
        .spy((io) => {
            // Setup minimal environment
            let id_payload = { ...f.MOCK_CLAIMS, sub: "user-123" };
            let id_token = crypto.sign_jws(id_payload, f.MOCK_CONFIG.client_secret);
            tokens.id_token = id_token;

            io.http_get = (url) => {
                if (index(url, "jwks") != -1) return { status: 200, body: { read: () => sprintf("%J", { keys: [{ kty: "oct", kid: "HS256", k: crypto.b64url_encode(f.MOCK_CONFIG.client_secret) }] }) } };
                return { status: 200, body: { read: () => sprintf("%J", f.MOCK_DISCOVERY) } };
            };
            io.http_post = (url) => ({ status: 200, body: { read: () => sprintf("%J", tokens) } });

            let state_res = handshake.initiate(io, test_config);
            let state_val = replace(state_res.data.url, /^.*state=([^&]+).*$/, "$1");
            let request = {
                path: "/callback",
                query: { code: "c1", state: state_val },
                cookies: { "__Host-luci_sso_state": state_res.data.token },
                env: { HTTPS: "on" }
            };

            handshake.authenticate(io, test_config, request, { allowed_algs: ["HS256"] });

            // Manual iteration check
            let found = false;
            for (let e in io.__state__.history) {
                if (e.type == "log" && e.args[0] == "warn" && match(e.args[1], /Access token lifetime exceeds 24h replay window/)) {
                    found = true;
                    break;
                }
            }
            assert(found, "Should log warning for long-lived access token");
        });
});

test('Handshake: Warning - Silent for opaque or short-lived tokens', () => {
    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: f.MOCK_CONFIG.issuer_url,
        redirect_uri: "https://r/c",
        user_mappings: [{ rpcd_user: "root", rpcd_password: "p", emails: ["user-123"] }]
    };

    let cases = [
        { name: "Opaque", token: "opaque_string_without_dots" },
        { name: "Short-lived", token: "h." + crypto.b64url_encode(sprintf("%J", { iat: 100, exp: 200 })) + ".s" }
    ];

    for (let c in cases) {
        mock.create()
            .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
            .with_ubus({ "session:login": { "ubus_rpc_session": "s1" }, "session:set": {} })
            .spy((io) => {
                let id_payload = { ...f.MOCK_CLAIMS, sub: "user-123" };
                let id_token = crypto.sign_jws(id_payload, f.MOCK_CONFIG.client_secret);
                let tokens = { access_token: c.token, id_token: id_token };
                
                io.http_get = (url) => {
                    if (index(url, "jwks") != -1) return { status: 200, body: { read: () => sprintf("%J", { keys: [{ kty: "oct", kid: "HS256", k: crypto.b64url_encode(f.MOCK_CONFIG.client_secret) }] }) } };
                    return { status: 200, body: { read: () => sprintf("%J", f.MOCK_DISCOVERY) } };
                };
                io.http_post = (url) => ({ status: 200, body: { read: () => sprintf("%J", tokens) } });

                let state_res = handshake.initiate(io, test_config);
                let state_val = replace(state_res.data.url, /^.*state=([^&]+).*$/, "$1");
                let request = {
                    path: "/callback",
                    query: { code: "c1", state: state_val },
                    cookies: { "__Host-luci_sso_state": state_res.data.token },
                    env: { HTTPS: "on" }
                };

                handshake.authenticate(io, test_config, request, { allowed_algs: ["HS256"] });

                let found = false;
                for (let e in io.__state__.history) {
                    if (e.type == "log" && e.args[0] == "warn" && match(e.args[1], /Access token lifetime exceeds 24h replay window/)) {
                        found = true;
                        break;
                    }
                }
                assert(!found, `Should NOT log warning for ${c.name} token`);
            });
    }
});