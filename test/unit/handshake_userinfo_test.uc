import { test, assert, assert_eq } from '../testing.uc';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';
import * as h from 'unit.helpers';

test('handshake: userinfo - supplements missing email when sub matches', () => {
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
        issuer_url: "https://trusted.idp",
        internal_issuer_url: "https://trusted.idp",
        roles: [ { name: "admin", emails: ["user@example.com"], read: ["*"], write: ["*"] } ]
    };

    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_ubus({ "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} })
        .spy((io) => {
            io.http_get = (url) => {
                if (url == issuer_url + "/.well-known/openid-configuration") 
                    return { status: 200, body: { read: () => sprintf("%J", discovery_doc) } };
                if (url == discovery_doc.jwks_uri) 
                    return { status: 200, body: { read: () => sprintf("%J", { keys: [ f.MOCK_JWK ] }) } };
                if (url == discovery_doc.userinfo_endpoint)
                    return { status: 200, body: { read: () => sprintf("%J", { sub: f.MOCK_CLAIMS.sub, email: "user@example.com" }) } };
                return { status: 404 };
            };

            io.http_post = (url) => {
                let access_token = "at-123";
                // ID Token WITHOUT email
                let payload = { ...f.MOCK_CLAIMS, email: null, nonce: "test-nonce", at_hash: crypto.b64url_encode(substr(crypto.sha256(access_token), 0, 16)) };
                let token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
                return { status: 200, body: { read: () => sprintf("%J", { access_token: access_token, id_token: token }) } };
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
            assert(res.ok, `Handshake should succeed with UserInfo. Error: ${res.error}`);
            assert_eq(res.data.email, "user@example.com", "Email should be supplemented from UserInfo");
        });
});

test('handshake: userinfo - fails identity binding when sub mismatches', () => {
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
        issuer_url: "https://trusted.idp",
        internal_issuer_url: "https://trusted.idp"
    };

    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .spy((io) => {
            io.http_get = (url) => {
                if (url == discovery_doc.userinfo_endpoint)
                    return { status: 200, body: { read: () => sprintf("%J", { sub: "EVIL-SUB", email: "evil@example.com" }) } };
                if (url == issuer_url + "/.well-known/openid-configuration") 
                    return { status: 200, body: { read: () => sprintf("%J", discovery_doc) } };
                if (url == discovery_doc.jwks_uri) 
                    return { status: 200, body: { read: () => sprintf("%J", { keys: [ f.MOCK_JWK ] }) } };
                return { status: 404 };
            };

            io.http_post = (url) => {
                let access_token = "at-456";
                let payload = { ...f.MOCK_CLAIMS, email: null, nonce: "test-nonce", at_hash: crypto.b64url_encode(substr(crypto.sha256(access_token), 0, 16)) };
                let token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
                return { status: 200, body: { read: () => sprintf("%J", { access_token: access_token, id_token: token }) } };
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
            assert(!res.ok, "Handshake should fail on sub mismatch");
            assert_eq(res.error, "IDENTITY_MISMATCH");
        });
});
