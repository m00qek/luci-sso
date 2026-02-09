import * as oidc from 'luci_sso.oidc';
import * as testing from 'testing';
import * as mock from 'mock';

testing.test("OIDC: Discovery - Reject insecure HTTP issuer", function() {
	let mocked = mock.create();
	mocked.with_responses({}, (io) => {
		let res = oidc.discover(io, "http://insecure.com");
		testing.assert(!res.ok, "Should fail for HTTP");
		testing.assert(res.error == "INSECURE_ISSUER_URL", "Wrong error code: " + res.error);
	});
});

testing.test("OIDC: Discovery - Reject insecure internal_issuer_url", function() {
	let mocked = mock.create();
	mocked.with_responses({}, (io) => {
		let res = oidc.discover(io, "https://secure.com", { internal_issuer_url: "http://insecure.local" });
		testing.assert(!res.ok, "Should fail for insecure internal URL");
		testing.assert(res.error == "INSECURE_FETCH_URL", "Wrong error code: " + res.error);
	});
});
