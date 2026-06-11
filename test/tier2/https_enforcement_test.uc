import { it, assert, falsy } from 'utest';
import * as oidc from 'luci_sso.oidc';

it('oidc: discovery - reject insecure HTTP issuer', () => {
	let res = oidc.discover({}, "http://insecure.com");
	assert.match(falsy(), res.ok, "Should fail for HTTP");
	assert.match("INSECURE_ISSUER_URL", res.error, "Wrong error code: " + res.error);
});

it('oidc: discovery - reject insecure internal issuer URL', () => {
	let res = oidc.discover({}, "https://secure.com", { internal_issuer_url: "http://insecure.local" });
	assert.match(falsy(), res.ok, "Should fail for insecure internal URL");
	assert.match("INSECURE_FETCH_URL", res.error, "Wrong error code: " + res.error);
});
