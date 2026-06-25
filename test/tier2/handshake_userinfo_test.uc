import { describe, it, assert, truthy, falsy } from 'utest';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

describe('handshake: userinfo', () => {
	it('supplements missing email when sub matches', () => {
		let test_config = {
			...f.MOCK_CONFIG,
			issuer_url: "https://trusted.idp",
			internal_issuer_url: "https://trusted.idp",
			roles: [ { name: "admin", emails: ["user@example.com"], read: ["*"], write: ["*"] } ]
		};

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[f.MOCK_DISCOVERY.userinfo_endpoint]: { status: 200, body: { sub: f.MOCK_CLAIMS.sub, email: "user@example.com" } }
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-123";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let payload = { ...f.MOCK_CLAIMS, email: null, nonce: "test-nonce", at_hash };
						let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = session.create_state(deps);
			assert.match(truthy(), s_res.ok);
			let s_data = s_res.data;
			let path = "/var/run/luci-sso/handshake_" + s_data.token + ".json";
			let raw_data = encoding.safe_json(deps.fs.readfile(path)).data;
			raw_data.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw_data));

			let request = {
				query: { code: "c1", state: raw_data.state },
				cookies: { "__Host-luci_sso_state": s_data.token }
			};

			let res = handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), res.ok, `Handshake should succeed with UserInfo. Error: ${res.error}`);
			assert.match("user@example.com", res.data.email, "Email should be supplemented from UserInfo");
		});
	});

	it('fails identity binding when sub mismatches', () => {
		let test_config = {
			...f.MOCK_CONFIG,
			issuer_url: "https://trusted.idp",
			internal_issuer_url: "https://trusted.idp"
		};

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			http_client: {
				data: {
					[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[f.MOCK_DISCOVERY.userinfo_endpoint]: { status: 200, body: { sub: "EVIL-SUB", email: "evil@example.com" } }
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-456";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data;
						let payload = { ...f.MOCK_CLAIMS, email: null, nonce: "test-nonce", at_hash };
						let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = session.create_state(deps);
			assert.match(truthy(), s_res.ok);
			let s_data = s_res.data;
			let path = "/var/run/luci-sso/handshake_" + s_data.token + ".json";
			let raw_data = encoding.safe_json(deps.fs.readfile(path)).data;
			raw_data.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw_data));

			let request = {
				query: { code: "c1", state: raw_data.state },
				cookies: { "__Host-luci_sso_state": s_data.token }
			};

			let res = handshake.authenticate(deps, test_config, request);
			assert.match(falsy(), res.ok, "Handshake should fail on sub mismatch");
			assert.match("IDENTITY_MISMATCH", res.error);
		});
	});
});
