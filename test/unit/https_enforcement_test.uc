import * as oidc from 'luci_sso.oidc';
import * as testing from 'testing';

testing.test("oidc.discover rejects insecure HTTP issuer", function() {
	let io = {
		http_get: () => ({ status: 200, body: "{}" }),
		time: () => 1000
	};
	
	let res = oidc.discover(io, "http://insecure.com");
	testing.assert(!res.ok, "Should fail for HTTP");
	testing.assert(res.error == "INSECURE_ISSUER_URL", "Wrong error code: " + res.error);
});

testing.test("oidc.discover rejects insecure internal_issuer_url", function() {
	let io = {
		http_get: () => ({ status: 200, body: "{}" }),
		time: () => 1000
	};
	
	let res = oidc.discover(io, "https://secure.com", { internal_issuer_url: "http://insecure.local" });
	testing.assert(!res.ok, "Should fail for insecure internal URL");
	testing.assert(res.error == "INSECURE_FETCH_URL", "Wrong error code: " + res.error);
});
