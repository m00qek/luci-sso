'use strict';

import { test, assert, assert_eq } from 'testing';
import * as handshake from 'luci_sso.handshake';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

test('handshake: security - state is consumed only once (B1)', () => {
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

	let data = mock.create()
		.with_files({ [path]: sprintf("%J", mock_handshake) })
		.with_responses({
			"https://idp.com/.well-known/openid-configuration": { status: 200, body: f.MOCK_DISCOVERY },
			"https://idp.com/token": { status: 400, body: { error: "invalid_grant" } } // Force failure
		});

	let spy_handle = data.spy((io) => {
		let req = {
			query: { code: "123", state: mock_handshake.state },
			cookies: { "__Host-luci_sso_state": handle }
		};

		handshake.authenticate(io, config, req);
	});

	let history = spy_handle.all();
	let remove_calls = 0;
	let rename_calls = 0;

	for (let entry in history) {
		if (entry.type == "remove" && index(entry.args[0], handle) != -1) {
			remove_calls++;
		}
		if (entry.type == "rename" && index(entry.args[0], handle) != -1) {
			rename_calls++;
		}
	}

	assert_eq(rename_calls, 1, "Should attempt rename exactly once");
	assert_eq(remove_calls, 1, "Should attempt remove exactly once (inside verify_state)");
});
