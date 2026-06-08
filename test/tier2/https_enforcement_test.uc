import { it, assert, truthy, falsy } from 'utest';
import * as oidc from 'luci_sso.oidc';
import * as mock from 'mock';

it('oidc: discovery - reject insecure HTTP issuer', () => {
	let mocked = mock.create();
	mocked.with_responses({}, (io) => {
		let res = oidc.discover(io, "http://insecure.com");
		assert.match(falsy(), res.ok, "Should fail for HTTP");
		assert.match("INSECURE_ISSUER_URL", res.error, "Wrong error code: " + res.error);
	});
});

it('oidc: discovery - reject insecure internal issuer URL', () => {
	let mocked = mock.create();
	mocked.with_responses({}, (io) => {
		let res = oidc.discover(io, "https://secure.com", { internal_issuer_url: "http://insecure.local" });
		assert.match(falsy(), res.ok, "Should fail for insecure internal URL");
		assert.match("INSECURE_FETCH_URL", res.error, "Wrong error code: " + res.error);
	});
});
