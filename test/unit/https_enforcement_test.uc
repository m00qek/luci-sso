import { test, assert, assert_eq } from 'testing';
import * as oidc from 'luci_sso.oidc';
import * as mock from 'mock';

test('oidc: discovery - reject insecure HTTP issuer', () => {
	let mocked = mock.create();
	mocked.with_responses({}, (io) => {
		let res = oidc.discover(io, "http://insecure.com");
		assert(!res.ok, "Should fail for HTTP");
		assert_eq(res.error, "INSECURE_ISSUER_URL", "Wrong error code: " + res.error);
	});
});

test('oidc: discovery - reject insecure internal issuer URL', () => {
	let mocked = mock.create();
	mocked.with_responses({}, (io) => {
		let res = oidc.discover(io, "https://secure.com", { internal_issuer_url: "http://insecure.local" });
		assert(!res.ok, "Should fail for insecure internal URL");
		assert_eq(res.error, "INSECURE_FETCH_URL", "Wrong error code: " + res.error);
	});
});
