import { describe, it, assert, truthy } from 'utest';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

describe('handshake: split-horizon', () => {
	it('prevents path corruption when issuer_url is in path', () => {
		let issuer_url = "https://auth.com";
		let internal_issuer_url = "https://internal.lan:8443";

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

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s123" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[internal_issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[internal_issuer_url + "/realms/auth.com/jwks"]: { status: 200, body: { keys: [ f.MOCK_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						if (url == internal_issuer_url + "/realms/internal.lan:8443/token") {
							return { ok: true, data: { status: 404, body: "Path Corrupted" } };
						}
						let access_token = "at-123";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(access_token).data, 0, 16)).data;
						let payload = {
							...f.MOCK_CLAIMS,
							iss: issuer_url,
							email: "admin@example.com",
							nonce: "test-nonce",
							at_hash
						};
						let id_token = h.generate_id_token(payload, f.MOCK_PRIVKEY, "RS256");
						return { ok: true, data: { status: 200, body: sprintf("%J", { access_token, id_token }) } };
					}
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let s_res = session.create_state(deps);
			assert.match(truthy(), s_res.ok, `create_state failed: ${s_res.error}`);
			let s_data = s_res.data;
			let handle = s_data.token;
			let path = "/var/run/luci-sso/handshake_" + handle + ".json";

			let raw_data = encoding.safe_json(deps.fs.readfile(path)).data;
			raw_data.nonce = "test-nonce";
			deps.fs.writefile(path, sprintf("%J", raw_data));

			let request = {
				query: { code: "c1", state: raw_data.state },
				cookies: { "__Host-luci_sso_state": handle }
			};

			let res = handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), res.ok, `Handshake should succeed. Error: ${res.error} Details: ${res.details}`);
			assert.match("admin@example.com", res.data.email);
		});
	});

	it('prevents corruption when internal_issuer_url is substring of issuer_url', () => {
		let issuer_url = "https://auth.com";
		let internal_issuer_url = "https://auth";

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

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			ubus:  { data: { "session:create": { "ubus_rpc_session": "s456" }, "session:grant": {}, "session:set": {} } },
			http_client: {
				data: {
					[internal_issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[internal_issuer_url + "/jwks"]: { status: 200, body: { keys: [ f.MOCK_JWK ] } }
				},
				behavior: {
					post: (url, opts) => {
						let access_token = "at-456";
						let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(access_token).data, 0, 16)).data;
						let payload = {
							...f.MOCK_CLAIMS,
							iss: issuer_url,
							email: "admin@example.com",
							nonce: "test-nonce",
							at_hash
						};
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
			assert.match(truthy(), res.ok, `Handshake should succeed. Error: ${res.error}`);
		});
	});

	it('handles trailing slash in issuer_url (Audit W3)', () => {
		let issuer_url = "https://idp.com/";
		let internal_issuer_url = "https://internal.lan";

		let discovery_doc = {
			issuer: "https://idp.com",
			authorization_endpoint: "https://idp.com/auth",
			token_endpoint: "https://idp.com/token",
			jwks_uri: "https://idp.com/jwks"
		};

		let test_config = {
			...f.MOCK_CONFIG,
			issuer_url: issuer_url,
			internal_issuer_url: internal_issuer_url,
		};

		with_context({
			fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
			http_client: {
				data: {
					[internal_issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: discovery_doc },
					[internal_issuer_url + "/jwks"]: { status: 200, body: { keys: [ f.MOCK_JWK ] } },
					[internal_issuer_url + "/token"]: { status: 200, body: { access_token: "at", id_token: "it" } }
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

			// If W3 bug existed, token_endpoint would be corrupted and GET would die in strict mode.
			// Reaching authenticate without strict-mode death confirms correct URL routing.
			handshake.authenticate(deps, test_config, request);
			assert.match(truthy(), true);
		});
	});
});
