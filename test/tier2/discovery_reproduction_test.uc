'use strict';

import { it, assert, falsy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import * as mock from 'mock';

it('discovery: reproduction - optional chaining crash with error response', () => {
	mock.create()
		.with_responses({
			"https://idp.com/.well-known/openid-configuration": { error: "MOCK_ERROR" }
		})
		.spy((io) => {
			let res = discovery.discover(io, "https://idp.com");
			assert.match(falsy(), res.ok, "Should return error, not crash");
		});
});

it('jwks: reproduction - optional chaining crash with error response', () => {
	mock.create()
		.with_responses({
			"https://idp.com/jwks": { error: "MOCK_ERROR" }
		})
		.spy((io) => {
			let res = discovery.fetch_jwks(io, "https://idp.com/jwks");
			assert.match(falsy(), res.ok, "Should return error, not crash");
		});
});
