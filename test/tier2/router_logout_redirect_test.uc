import { it, assert, truthy } from 'utest';
import * as router from 'luci_sso.router';
import { with_context } from 'context';

const TEST_POLICY = { allowed_algs: ["RS256"] };

const MOCK_DISC_DOC = {
	issuer: "https://idp.com",
	authorization_endpoint: "https://idp.com/auth",
	token_endpoint: "https://idp.com/token",
	jwks_uri: "https://idp.com/jwks",
	end_session_endpoint: "https://idp.com/logout"
};

it('router: logic - logout redirect derivation robustness (W3)', () => {
	let session_data = {
		"session:get": (args) => ({ values: { oidc_id_token: "hint", token: "csrf" } }),
		"session:destroy": {}
	};
	let discovery_data = {
		"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC }
	};

	// Test Case 1: Standard redirect_uri
	with_context({
		fs:          { data: {} },
		ubus:        { data: session_data },
		http_client: { data: discovery_data },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let config = { issuer_url: "https://idp.com", redirect_uri: "https://router.lan/cgi-bin/luci-sso/callback" };
		let req = { path: "/logout", query: { stoken: "csrf" }, cookies: { sysauth: "sid" } };
		let res = router.handle(deps, config, req, TEST_POLICY);
		assert.match(truthy(), res.ok);
		assert.match(truthy(), index(res.data.headers["Location"], "post_logout_redirect_uri=https%3A%2F%2Frouter.lan%2F") != -1);
	});

	// Test Case 2: Malformed redirect_uri (missing https://)
	with_context({
		fs:          { data: {} },
		ubus:        { data: session_data },
		http_client: { data: discovery_data },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let config = { issuer_url: "https://idp.com", redirect_uri: "ftp://router.lan/callback" };
		let req = { path: "/logout", query: { stoken: "csrf" }, cookies: { sysauth: "sid" } };
		let res = router.handle(deps, config, req, TEST_POLICY);
		assert.match(truthy(), res.ok);
		assert.match(-1, index(res.data.headers["Location"], "post_logout_redirect_uri="), "Should OMIT post_logout_redirect_uri for invalid redirect_uri scheme");
	});
});
