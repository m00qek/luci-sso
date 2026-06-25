import { describe, it, assert, truthy } from 'utest';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import * as encoding from 'luci_sso.encoding';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

describe('handshake: recovery', () => {
	it('handle JWKS key rotation with automatic retry', () => {
		let access_token = "access-token-123";
		let test_config = {
			...f.MOCK_CONFIG,
			internal_issuer_url: f.MOCK_CONFIG.issuer_url,
			redirect_uri: "https://r/c",
			roles: [
				{ name: "r1", emails: ["user-123"], read: ["*"], write: ["*"] }
			]
		};

		let jwks_uri = f.MOCK_DISCOVERY.jwks_uri;
		let old_jwks = { keys: [ f.MOCK_JWK ] };
		let new_jwks = { keys: [ f.ROTATION_NEW_JWK ] };
		let call_count = 0;

		let pending_tokens = { access_token: null, id_token: null };

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				behavior: {
					get: (url, opts) => {
						if (url == f.MOCK_DISCOVERY.issuer + "/.well-known/openid-configuration")
							return { ok: true, data: { status: 200, body: sprintf("%J", f.MOCK_DISCOVERY) } };
						if (url == jwks_uri) {
							call_count++;
							let data = (call_count == 1) ? old_jwks : new_jwks;
							return { ok: true, data: { status: 200, body: sprintf("%J", data) } };
						}
						return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
					},
					post: (url, opts) => {
						return { ok: true, data: { status: 200, body: sprintf("%J", pending_tokens) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let state_res = session.create_state(deps);
			assert.match(truthy(), state_res.ok);
			let s_data = state_res.data;

			let payload = {
				...f.MOCK_CLAIMS,
				email: "user-123",
				nonce: s_data.nonce,
				at_hash: encoding.b64url_encode(substr(crypto.hash_sha256(native, access_token).data, 0, 16)).data
			};
			pending_tokens.access_token = access_token;
			pending_tokens.id_token = h.generate_id_token(payload, f.ROTATION_NEW_PRIVKEY, "RS256", f.ROTATION_NEW_JWK.kid);

			let request = {
				query: { code: "c1", state: s_data.state },
				cookies: { "__Host-luci_sso_state": s_data.token }
			};

			let res = handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), res.ok, `Handshake should succeed after JWKS retry (Error: ${res.error}, Details: ${res.details})`);
			assert.match(2, call_count, "JWKS should have been fetched exactly twice (initial + forced refresh)");
		});
	});
});
