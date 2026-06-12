'use strict';

import { describe, it, assert, falsy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import { with_context } from 'context';

describe('discovery: reproduction', () => {
	it('optional chaining crash with error response', () => {
		with_context({
			fs:          { data: {} },
			http_client: { data: { "https://idp.com/.well-known/openid-configuration": { error: "MOCK_ERROR" } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let res = discovery.discover(deps, "https://idp.com");
			assert.match(falsy(), res.ok, "Should return error, not crash");
		});
	});
});

describe('jwks: reproduction', () => {
	it('optional chaining crash with error response', () => {
		with_context({
			fs:          { data: {} },
			http_client: { data: { "https://idp.com/jwks": { error: "MOCK_ERROR" } } },
			clock:       { data: { now: 1516239022 } }
		}, (deps) => {
			let res = discovery.fetch_jwks(deps, "https://idp.com/jwks");
			assert.match(falsy(), res.ok, "Should return error, not crash");
		});
	});
});
