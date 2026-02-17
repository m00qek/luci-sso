import { test, assert, assert_eq } from 'testing';
import * as router from 'luci_sso.router';
import * as Result from 'luci_sso.result';
import * as mock from 'mock';

const TEST_POLICY = { allowed_algs: ["RS256"] };
const MOCK_DISC_DOC = { 
	issuer: "https://idp.com", 
	authorization_endpoint: "https://idp.com/auth",
	token_endpoint: "https://idp.com/token",
	jwks_uri: "https://idp.com/jwks",
	end_session_endpoint: "https://idp.com/logout"
};

test('router: logic - logout redirect derivation robustness (W3)', () => {
	let factory = mock.create()
		.with_ubus({ 
			"session:get": (args) => ({ values: { oidc_id_token: "hint", token: "csrf" } }),
			"session:destroy": {} 
		})
		.with_responses({
			"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC }
		});

	// Test Case 1: Standard redirect_uri
	factory.with_env({}, (io) => {
		let config = { issuer_url: "https://idp.com", redirect_uri: "https://router.lan/cgi-bin/luci-sso/callback" };
		let req = { path: "/logout", query: { stoken: "csrf" }, cookies: { sysauth: "sid" } };
		let res = router.handle(io, config, req, TEST_POLICY);
		assert(res.ok);
		assert(index(res.data.headers["Location"], "post_logout_redirect_uri=https%3A%2F%2Frouter.lan%2F") != -1);
	});

	// Test Case 2: Malformed redirect_uri (missing https://)
	// This shouldn't happen due to config.uc validation, but testing for robustness
	factory.with_env({}, (io) => {
		let config = { issuer_url: "https://idp.com", redirect_uri: "ftp://router.lan/callback" };
		let req = { path: "/logout", query: { stoken: "csrf" }, cookies: { sysauth: "sid" } };
		let res = router.handle(io, config, req, TEST_POLICY);
		assert(res.ok);
		// Current logic: replace() doesn't match, returns original string
		// Result: ...post_logout_redirect_uri=ftp%3A%2F%2Frouter.lan%2Fcallback
		// Should ideally fallback to "/" if the regex fails to extract a safe origin.
		assert(index(res.data.headers["Location"], "post_logout_redirect_uri=%2F") != -1, "Should fallback to / for invalid redirect_uri scheme");
	});
});
