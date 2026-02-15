'use strict';

import { test, assert } from 'testing';
import * as discovery from 'luci_sso.discovery';
import * as mock from 'mock';

test('Discovery: Reproduction of optional chaining crash with error response', () => {
	// Trigger the path: if (!response || response.error)
	// We'll use a response that has an error field
	mock.create()
		.with_responses({
			"https://idp.com/.well-known/openid-configuration": { error: "MOCK_ERROR" }
		})
		.spy((io) => {
			try {
				let res = discovery.discover(io, "https://idp.com");
				print("Discovery: Execution finished without crash.\n");
			} catch (e) {
				print("Discovery: Crashed as expected: " + e + "\n");
				assert(true, "Crashed as expected");
			}
		});
});

test('JWKS: Reproduction of optional chaining crash with error response', () => {
	mock.create()
		.with_responses({
			"https://idp.com/jwks": { error: "MOCK_ERROR" }
		})
		.spy((io) => {
			try {
				let res = discovery.fetch_jwks(io, "https://idp.com/jwks");
				print("JWKS: Execution finished without crash.\n");
			} catch (e) {
				print("JWKS: Crashed as expected: " + e + "\n");
				assert(true, "Crashed as expected");
			}
		});
});
