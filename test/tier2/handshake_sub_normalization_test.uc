import { describe, it, assert, truthy } from 'utest';
import * as handshake from 'luci_sso.handshake';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

const TEST_POLICY = { allowed_algs: ["RS256", "ES256"] };

describe('handshake: reproduction', () => {
	it('userinfo fallback fails on case-mismatched sub', () => {
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

		let nonce_captured = null;

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[discovery_doc.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[discovery_doc.userinfo_endpoint]: { status: 200, body: { sub: "USER-123", email: "user@example.com" } }
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-123";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(access_token).data, 0, 16)).data;
						// ID Token has lowercase sub; UserInfo returns UPPERCASE sub — normalization must reconcile
						let payload = { ...f.MOCK_CLAIMS, sub: "user-123", email: null, nonce: nonce_captured, at_hash };
						let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = handshake.initiate(deps, test_config);
			assert.match(truthy(), s_res.ok, `initiate failed: ${s_res.error}`);

			nonce_captured = replace(s_res.data.url, /^.*nonce=([^&]+).*$/, "$1");
			let state_in_url = replace(s_res.data.url, /^.*state=([^&]+).*$/, "$1");

			let request = {
				query: { code: "c123", state: state_in_url },
				cookies: { "__Host-luci_sso_state": s_res.data.token }
			};

			let res = handshake.authenticate(deps, test_config, request, TEST_POLICY);
			assert.match(truthy(), res.ok, "Should SUCCEED after sub normalization fix");
			assert.match("user@example.com", res.data.email);
		});
	});
});
