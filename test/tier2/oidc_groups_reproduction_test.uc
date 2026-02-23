import { test, assert, assert_eq } from 'testing';
import * as oidc from 'luci_sso.oidc';
import * as handshake from 'luci_sso.handshake';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

const TEST_POLICY = { allowed_algs: ["RS256", "ES256"] };

test('REPRODUCTION: oidc: verify_id_token drops groups claim', () => {
	let keys = [ f.MOCK_JWK ];
	let at = "mock-at";
	let ah = crypto.b64url_encode(substr(crypto.sha256(at), 0, 16));
	
	let groups = ["admin", "dev"];
	let payload = { ...f.MOCK_CLAIMS, at_hash: ah, groups: groups };
	let token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");

	mock.create().with_env({}, (io) => {
		let res = oidc.verify_id_token(io, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, io.time(), TEST_POLICY);
		assert(res.ok, "Verification should succeed");
		assert(res.data.groups, "Groups claim SHOULD be present in user_data");
		assert_eq(res.data.groups, groups, "Groups claim SHOULD match original");
	});
});

test('REPRODUCTION: handshake: userinfo fallback drops groups claim', () => {
    let issuer_url = f.MOCK_CONFIG.issuer_url;
    let discovery_doc = {
        ...f.MOCK_DISCOVERY,
        authorization_endpoint: "https://trusted.idp/auth",
        token_endpoint: "https://trusted.idp/token",
        jwks_uri: "https://trusted.idp/jwks",
        userinfo_endpoint: "https://trusted.idp/userinfo"
    };

    let groups = ["idp-admin"];
    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: "https://trusted.idp",
        roles: [ { name: "admin", groups: ["idp-admin"], emails: ["user@example.com"], read: ["*"], write: ["*"] } ]
    };

    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_ubus({ "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} })
        .with_responses({
            [issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
            [discovery_doc.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
            [discovery_doc.userinfo_endpoint]: { status: 200, body: { sub: f.MOCK_CLAIMS.sub, email: "user@example.com", groups: groups } }
        })
        .spy((io) => {
            // We need to capture the nonce from the handshake to generate a valid ID Token
            let captured_nonce = null;
            let original_write_file = io.write_file;
            io.write_file = (path, data) => {
                if (match(path, /handshake_.*\.json/)) {
                    let res = crypto.safe_json(data);
                    if (res.ok) {
                        captured_nonce = res.data.nonce;
                    }
                }
                return original_write_file(path, data);
            };

            io.http_post = (url, opts) => {
                if (url == discovery_doc.token_endpoint) {
                    let access_token = "at-123";
                    let payload = { 
                        ...f.MOCK_CLAIMS, 
                        email: null, 
                        groups: null, 
                        nonce: captured_nonce, 
                        at_hash: crypto.b64url_encode(substr(crypto.sha256(access_token), 0, 16)) 
                    };
                    let token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
                    return { status: 200, body: { read: () => sprintf("%J", { access_token: access_token, id_token: token }) } };
                }
                return { status: 404 };
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
            
            if (!res.ok) {
                printf("AUTHENTICATE FAILED: %s (Details: %J)\n", res.error, res.details);
            }
            assert(res.ok, "Authentication should succeed");
            // If groups was preserved, it would match the "admin" role.
            // But we need to verify if user_data passed to create_passwordless_session has groups.
            // Since we can't easily inspect internal state, we can check if the session was created with the correct role.
            // If groups is dropped, it will fail with USER_NOT_AUTHORIZED because neither email nor groups match.
        });
});
