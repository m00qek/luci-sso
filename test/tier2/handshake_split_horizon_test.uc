import { test, assert, assert_eq } from 'testing';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

test('handshake: split-horizon - prevents path corruption when issuer_url is in path', () => {
    // BUG: If issuer_url is "https://auth.com" and token_endpoint is "https://auth.com/realms/auth.com/token",
    // naive replace() results in "https://internal/realms/internal/token" if internal_issuer_url is "https://internal".
    
    let issuer_url = "https://auth.com";
    let internal_issuer_url = "https://internal.lan:8443";
    
    // An IdP where the issuer URL appears in the path
    let discovery_doc = {
        issuer: issuer_url,
        authorization_endpoint: issuer_url + "/auth",
        token_endpoint: issuer_url + "/realms/auth.com/token",
        jwks_uri: issuer_url + "/realms/auth.com/jwks",
        userinfo_endpoint: issuer_url + "/realms/auth.com/userinfo"
    };

    let test_config = {
        ...f.MOCK_CONFIG,
        issuer_url: issuer_url,
        internal_issuer_url: internal_issuer_url,
        redirect_uri: "https://router/callback",
        roles: [
            { name: "admin", emails: ["admin@example.com"], read: ["*"], write: ["*"] }
        ]
    };

    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_uci({
            "luci-sso": {
                "default": { ...test_config, ".type": "oidc", "enabled": "1" }
            }
        })
        .with_ubus({
            "session:create": { "ubus_rpc_session": "s123" },
            "session:grant": {},
            "session:set": {}
        })
        .spy((io) => {
            io.http_get = (url) => {
                if (url == internal_issuer_url + "/.well-known/openid-configuration") {
                    return { status: 200, body: { read: () => sprintf("%J", discovery_doc) } };
                }
                // If the bug exists, this will be called with the corrupted URL
                if (url == internal_issuer_url + "/realms/auth.com/jwks") {
                    return { status: 200, body: { read: () => sprintf("%J", { keys: [ f.MOCK_JWK ] }) } };
                }
                if (url == internal_issuer_url + "/realms/internal.lan:8443/jwks") {
                     // This is what we expect if naive replace is used
                     return { status: 404, body: { read: () => "Path Corrupted" } };
                }
                return { status: 404, body: { read: () => "" } };
            };

            io.http_post = (url, body, options) => {
                // VERIFICATION: Check if the URL is corrupted
                if (url == internal_issuer_url + "/realms/internal.lan:8443/token") {
                    return { status: 404, body: { read: () => "Path Corrupted" } };
                }
                
                if (url == internal_issuer_url + "/realms/auth.com/token") {
                    let access_token = "at-123";
                    let payload = { 
                        ...f.MOCK_CLAIMS,
                        iss: issuer_url,
                        email: "admin@example.com",
                        nonce: "test-nonce",
                        at_hash: crypto.b64url_encode(substr(crypto.sha256(access_token), 0, 16))
                    };
                    let token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
                    return { 
                        status: 200, 
                        body: { read: () => sprintf("%J", { access_token: access_token, id_token: token }) } 
                    };
                }
                return { status: 404, body: { read: () => "" } };
            };

            let s_res = session.create_state(io);
            if (!s_res.ok) {
                print("create_state failed: ", s_res.error, "\n");
                assert(false);
            }
            let s_data = s_res.data;
            let handle = s_data.token;
            let path = "/var/run/luci-sso/handshake_" + handle + ".json";
            
            let content = io.read_file(path);
            let json_res = crypto.safe_json(content);
            if (!json_res.ok) {
                print("Failed to parse handshake state from: ", path, " (", json_res.details, ")\n");
                assert(false);
            }
            let raw_data = json_res.data;
            raw_data.nonce = "test-nonce";
            io.write_file(path, sprintf("%J", raw_data));

            let request = {
                path: "/callback",
                query: { code: "c1", state: raw_data.state },
                cookies: { "__Host-luci_sso_state": handle },
                env: { HTTPS: "on" }
            };

            let res = handshake.authenticate(io, test_config, request);
            
            assert(res.ok, `Handshake should succeed. Error: ${res.error} Details: ${res.details}`);
            assert_eq(res.data.email, "admin@example.com");
        });
});

test('handshake: split-horizon - prevents corruption when internal_issuer_url is substring of issuer_url', () => {
    // SCENARIO: issuer_url is "https://auth.com", internal_issuer_url is "https://auth".
    // If endpoint is "https://auth.com/token", naive replace results in "https://auth.com/token" -> "https://auth.com/token" (no change) or worse if reversed.
    // Actually the previous BUG was global replace.
    
    let issuer_url = "https://auth.com";
    let internal_issuer_url = "https://auth"; // Unusual but possible
    
    let discovery_doc = {
        issuer: issuer_url,
        authorization_endpoint: issuer_url + "/auth",
        token_endpoint: issuer_url + "/token",
        jwks_uri: issuer_url + "/jwks"
    };

    let test_config = {
        ...f.MOCK_CONFIG,
        issuer_url: issuer_url,
        internal_issuer_url: internal_issuer_url,
        redirect_uri: "https://router/callback",
        roles: [ { name: "admin", emails: ["admin@example.com"], read: ["*"], write: ["*"] } ]
    };

    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_ubus({
            "session:create": { "ubus_rpc_session": "s456" },
            "session:grant": {},
            "session:set": {}
        })
        .spy((io) => {
            io.http_get = (url) => {
                if (url == internal_issuer_url + "/.well-known/openid-configuration") {
                    return { status: 200, body: { read: () => sprintf("%J", discovery_doc) } };
                }
                if (url == internal_issuer_url + "/jwks") {
                    return { status: 200, body: { read: () => sprintf("%J", { keys: [ f.MOCK_JWK ] }) } };
                }
                return { status: 404 };
            };

            io.http_post = (url) => {
                if (url == internal_issuer_url + "/token") {
                    let access_token = "at-456";
                    let payload = { 
                        ...f.MOCK_CLAIMS, 
                        iss: issuer_url,
                        email: "admin@example.com", 
                        nonce: "test-nonce",
                        at_hash: crypto.b64url_encode(substr(crypto.sha256(access_token), 0, 16))
                    };
                    let token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
                    return { status: 200, body: { read: () => sprintf("%J", { access_token: access_token, id_token: token }) } };
                }
                return { status: 404 };
            };

            let s_res = session.create_state(io);
            let s_data = s_res.data;
            let path = "/var/run/luci-sso/handshake_" + s_data.token + ".json";
            let raw_data = crypto.safe_json(io.read_file(path)).data;
            raw_data.nonce = "test-nonce";
            io.write_file(path, sprintf("%J", raw_data));

            let request = {
                path: "/callback",
                query: { code: "c1", state: raw_data.state },
                cookies: { "__Host-luci_sso_state": s_data.token },
                env: { HTTPS: "on" }
            };

            let res = handshake.authenticate(io, test_config, request);
            assert(res.ok, `Handshake should succeed with internal_issuer_url as substring. Error: ${res.error}`);
        });
});
