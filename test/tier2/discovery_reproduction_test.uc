'use strict';

import { it, assert, falsy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import * as mock from 'mock';

function make_discovery_deps(io) {
	return {
		fs: {
			readfile:  (p)    => io.read_file(p),
			writefile: (p, d) => io.write_file(p, d),
			unlink:    (p)    => io.remove(p),
			rename:    (o, n) => io.rename(o, n),
		},
		http:  { get: (url, opts) => io.http_get(url, opts) },
		clock: { time: () => io.time() },
		log: io.log
	};
}

it('discovery: reproduction - optional chaining crash with error response', () => {
	mock.create()
		.with_responses({
			"https://idp.com/.well-known/openid-configuration": { error: "MOCK_ERROR" }
		})
		.spy((io) => {
			let res = discovery.discover(make_discovery_deps(io), "https://idp.com");
			assert.match(falsy(), res.ok, "Should return error, not crash");
		});
});

it('jwks: reproduction - optional chaining crash with error response', () => {
	mock.create()
		.with_responses({
			"https://idp.com/jwks": { error: "MOCK_ERROR" }
		})
		.spy((io) => {
			let res = discovery.fetch_jwks(make_discovery_deps(io), "https://idp.com/jwks");
			assert.match(falsy(), res.ok, "Should return error, not crash");
		});
});
