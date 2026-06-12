import { it, assert, truthy, falsy, spy } from 'utest';
import * as Result from 'luci_sso.result';
import * as oidc from 'luci_sso.oidc';
import * as handshake from 'luci_sso.handshake';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';

it('oidc: security - reject massive discovery response (DoS protection)', () => {
	// Generate a response slightly larger than 256KB using exponential doubling
	let garbage = "1234567890";
	for (let i = 0; i < 15; i++) garbage += garbage; // 10 * 2^15 = 327,680 chars (~320KB)
	let massive_body = { ...f.MOCK_DISCOVERY, garbage };

	with_context({
		http_client: {
			data: { "https://massive.idp/.well-known/openid-configuration": { status: 200, body: massive_body } }
		}
	}, (deps) => {
		let res = oidc.discover(deps, "https://massive.idp");

		assert.match(falsy(), res.ok, "Should reject massive discovery document");
		assert.match("DISCOVERY_NETWORK_ERROR", res.error, "Should return network error (aborted read)");
	});
});

it('handshake: security - register_token deferred until after verification (DoS prevention)', () => {
	let test_config = {
		...f.MOCK_CONFIG,
		internal_issuer_url: f.MOCK_CONFIG.issuer_url,
		redirect_uri: "https://r/c",
		roles: [{ name: "admin", emails: ["user-123"], read: ["*"], write: ["*"] }]
	};

	with_context({
		fs: { data: {} },
		http_client: {
			behavior: {
				get: (url, opts) => {
					return { ok: true, data: { status: 200, body: sprintf("%J", f.MOCK_DISCOVERY) } };
				},
				post: (url, opts) => {
					return { ok: true, data: { status: 200, body: sprintf("%J", { access_token: "at1", id_token: "invalid.id.token" }) } };
				}
			}
		},
		clock: { data: { now: 1516239022 } }
	}, (deps) => {
		let state_res = handshake.initiate(deps, test_config);
		assert.match(truthy(), state_res.ok, "initiate should succeed");
		let state_val = replace(state_res.data.url, /^.*state=([^&]+).*$/, "$1");
		let request = {
			path: "/callback",
			query: { code: "c1", state: state_val },
			cookies: { "__Host-luci_sso_state": state_res.data.token },
			env: { HTTPS: "on" }
		};

		let auth_res = handshake.authenticate(deps, test_config, request, { allowed_algs: ["RS256"] });
		assert.match(falsy(), auth_res.ok, "Authentication should fail due to invalid ID token");

		// Verify token was NOT registered by checking fs.mkdir was never called with a token path
		let mkdir_calls = spy(deps.fs).calls.mkdir;
		let token_registered = false;
		for (let call in mkdir_calls) {
			if (call[0] && index(call[0], "/tokens/") != -1) {
				token_registered = true;
				break;
			}
		}
		assert.match(falsy(), token_registered, "Should NOT register token before successful ID token verification");
	});
});
