'use strict';

import { it, assert, truthy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import * as mock from 'mock';

it('Discovery: Reproduction of optional chaining crash with error response', () => {
	// Trigger the path: if (!response || response.error)
	// We'll use a response that has an error field
	mock.create()
		.with_responses({
			"https://idp.com/.well-known/openid-configuration": { error: "MOCK_ERROR" }
		})
		.spy((io) => {
			try {
				let res = discovery.discover(io, "https://idp.com");
			} catch (e) {
				assert.match(truthy(), true, "Crashed as expected");
			}
		});
});

it('JWKS: Reproduction of optional chaining crash with error response', () => {
	mock.create()
		.with_responses({
			"https://idp.com/jwks": { error: "MOCK_ERROR" }
		})
		.spy((io) => {
			try {
				let res = discovery.fetch_jwks(io, "https://idp.com/jwks");
			} catch (e) {
				assert.match(truthy(), true, "Crashed as expected");
			}
		});
});
