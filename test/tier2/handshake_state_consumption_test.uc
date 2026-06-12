'use strict';

import { describe, it, assert, truthy, spy } from 'utest';
import * as handshake from 'luci_sso.handshake';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';

describe('handshake: security', () => {
	it('state is consumed only once (B1)', () => {
		let handle = "valid-handle";
		let path = `/var/run/luci-sso/handshake_${handle}.json`;
		let config = { ...f.MOCK_CONFIG, clock_tolerance: 30 };

		let mock_handshake = {
			id: "h123",
			state: "state123",
			nonce: "nonce123",
			code_verifier: "verifier123-verifier123-verifier123-verifier123",
			iat: 1516239022,
			exp: 1516239022 + 300
		};

		let rename_calls_arr = null;
		let unlink_calls_arr = null;

		with_context({
			fs: { data: { [path]: sprintf("%J", mock_handshake) } },
			http_client: {
				data: {
					[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY },
					[f.MOCK_DISCOVERY.token_endpoint]: { status: 400, body: { error: "invalid_grant" } }
				}
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let req = {
				query: { code: "123", state: mock_handshake.state },
				cookies: { "__Host-luci_sso_state": handle }
			};

			handshake.authenticate(deps, config, req);

			rename_calls_arr = spy(deps.fs).calls.rename || [];
			unlink_calls_arr = spy(deps.fs).calls.unlink || [];
		});

		let rename_calls = 0;
		for (let c in rename_calls_arr) {
			if (index(c[0], handle) != -1) rename_calls++;
		}

		let remove_calls = 0;
		for (let c in unlink_calls_arr) {
			if (index(c[0], handle) != -1) remove_calls++;
		}

		assert.match(1, rename_calls, "Should attempt rename exactly once");
		assert.match(1, remove_calls, "Should attempt remove exactly once (inside verify_state)");
	});
});
