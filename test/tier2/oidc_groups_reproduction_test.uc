import { describe, it, assert, truthy } from 'utest';
import * as oidc from 'luci_sso.oidc';
import * as handshake from 'luci_sso.handshake';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

const TEST_POLICY = { allowed_algs: ["RS256", "ES256"] };

describe('oidc: reproduction', () => {
	it('verify_id_token drops groups claim', () => {
		let keys = [ f.MOCK_JWK ];
		let at = "mock-at";
		let ah = encoding.b64url_encode(substr(crypto.hash_sha256(native, at).data, 0, 16)).data;
		let groups = ["admin", "dev"];
		let payload = { ...f.MOCK_CLAIMS, at_hash: ah, groups: groups };
		let token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");

		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token: at }, keys, f.MOCK_CONFIG, { nonce: "n" }, f.MOCK_DISCOVERY, 1516239022, TEST_POLICY);
			assert.match(truthy(), res.ok, "Verification should succeed");
			assert.match(truthy(), res.data.groups, "Groups claim SHOULD be present in user_data");
			assert.match(groups, res.data.groups, "Groups claim SHOULD match original");
		});
	});
});

describe('handshake: reproduction', () => {
	it('userinfo fallback drops groups claim', () => {
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
		let nonce_ref = null;

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[discovery_doc.jwks_uri]:          { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[discovery_doc.userinfo_endpoint]: { status: 200, body: { sub: f.MOCK_CLAIMS.sub, email: "user@example.com", groups: groups } }
				},
				behavior: {
					post: (url, opts) => {
						if (url == discovery_doc.token_endpoint) {
							let access_token = "at-123";
							let payload = {
								...f.MOCK_CLAIMS,
								email: null,
								groups: null,
								nonce: nonce_ref,
								at_hash: encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data
							};
							let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
							return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
						}
						return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = handshake.initiate(deps, test_config);
			assert.match(truthy(), s_res.ok, `initiate failed: ${s_res.error}`);
			nonce_ref = replace(s_res.data.url, /^.*nonce=([^&]+).*$/, "$1");
			let state_val = replace(s_res.data.url, /^.*state=([^&]+).*$/, "$1");
			let request = {
				query: { code: "c123", state: state_val },
				cookies: { "__Host-luci_sso_state": s_res.data.token }
			};
			let res = handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), res.ok, `Authentication should succeed (Error: ${res.error}, Details: ${res.details})`);
		});
	});
});
