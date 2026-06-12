import { describe, it, assert, truthy, falsy } from 'utest';
import * as handshake from 'luci_sso.handshake';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

describe('handshake: warning', () => {
	it('log warning for long-lived access tokens (W2)', () => {
		let now = 1516239022;
		let payload = { iat: now, exp: now + 90000 };
		let long_lived_token = "header." + encoding.b64url_encode(sprintf("%J", payload)).data + ".signature";

		let test_config = {
			...f.MOCK_CONFIG,
			internal_issuer_url: f.MOCK_CONFIG.issuer_url,
			redirect_uri: "https://r/c",
			roles: [{ name: "admin", emails: ["user-123"], read: ["*"], write: ["*"] }]
		};

		let log_calls = [];
		let nonce_ref = null;

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s1" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(long_lived_token).data, 0, 16)).data;
						let id_payload = { ...f.MOCK_CLAIMS, sub: "user-123", email: "user-123", nonce: nonce_ref, at_hash };
						let id_token = h.generate_id_token(id_payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token: long_lived_token, id_token }) } };
					}
				}
			},
			clock: { data: { now } }
		}, (deps) => {
			deps.log = (level, msg) => push(log_calls, [level, msg]);

			let state_res = handshake.initiate(deps, test_config);
			assert.match(truthy(), state_res.ok, `initiate failed: ${state_res.error}`);

			nonce_ref = replace(state_res.data.url, /^.*nonce=([^&]+).*$/, "$1");
			let state_val = replace(state_res.data.url, /^.*state=([^&]+).*$/, "$1");

			let request = {
				query: { code: "c1", state: state_val },
				cookies: { "__Host-luci_sso_state": state_res.data.token }
			};

			let auth_res = handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), auth_res.ok, `authenticate failed: ${auth_res.error} ${auth_res.details}`);
		});

		let found = false;
		for (let e in log_calls) {
			if (e[0] == "warn" && match(e[1], /Access token lifetime exceeds 24h replay window/)) {
				found = true;
				break;
			}
		}
		assert.match(truthy(), found, "Should log warning for long-lived access token");
	});

	it('silent for opaque or short-lived tokens', () => {
		let test_config = {
			...f.MOCK_CONFIG,
			internal_issuer_url: f.MOCK_CONFIG.issuer_url,
			redirect_uri: "https://r/c",
			roles: [{ name: "admin", emails: ["user-123"], read: ["*"], write: ["*"] }]
		};

		let cases = [
			{ name: "Opaque", token: "opaque_string_without_dots" },
			{ name: "Short-lived", token: "h." + encoding.b64url_encode(sprintf("%J", { iat: 100, exp: 200 })).data + ".s" }
		];

		for (let c in cases) {
			let log_calls = [];
			let nonce_ref = null;
			let access_token = c.token;

			with_context({
				fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
				ubus:  { data: { "session:create": { "ubus_rpc_session": "s1" }, "session:grant": {}, "session:set": {} } },
				http_client: {
					data: {
						[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
						[f.MOCK_DISCOVERY.jwks_uri]: { status: 200, body: { keys: [ f.MOCK_JWK ] } }
					},
					behavior: {
						post: (url, opts) => {
							let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(access_token).data, 0, 16)).data;
							let id_payload = { ...f.MOCK_CLAIMS, sub: "user-123", email: "user-123", nonce: nonce_ref, at_hash };
							let id_token = h.generate_id_token(id_payload, f.MOCK_PRIVKEY, "RS256");
							return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
						}
					}
				},
				clock: { data: { now: 1516239022 } }
			}, (deps) => {
				deps.log = (level, msg) => push(log_calls, [level, msg]);

				let state_res = handshake.initiate(deps, test_config);
				assert.match(truthy(), state_res.ok, `[${c.name}] initiate failed: ${state_res.error}`);

				nonce_ref = replace(state_res.data.url, /^.*nonce=([^&]+).*$/, "$1");
				let state_val = replace(state_res.data.url, /^.*state=([^&]+).*$/, "$1");

				let request = {
					query: { code: "c1", state: state_val },
					cookies: { "__Host-luci_sso_state": state_res.data.token }
				};

				let auth_res = handshake.authenticate(deps, test_config, request);
				assert.match(truthy(), auth_res.ok, `[${c.name}] authenticate failed: ${auth_res.error} ${auth_res.details}`);
			});

			let found = false;
			for (let e in log_calls) {
				if (e[0] == "warn" && match(e[1], /Access token lifetime exceeds 24h replay window/)) {
					found = true;
					break;
				}
			}
			assert.match(falsy(), found, `Should NOT log warning for ${c.name} token`);
		}
	});
});
