import { it, assert, truthy } from 'utest';
import * as router from 'luci_sso.router';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';

it('router: security - B1: handle invalid session during logout', () => {
	let test_config = { ...f.MOCK_CONFIG, issuer_url: "https://trusted.idp" };
	let discovery_with_logout = { ...f.MOCK_DISCOVERY, end_session_endpoint: "https://idp.com/logout" };

	with_context({
		fs:          { data: {} },
		ubus:        { data: { "session:get": () => null } },
		http_client: { data: {
			"https://trusted.idp/.well-known/openid-configuration": {
				status: 200, body: discovery_with_logout
			}
		} },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let request = {
			path: "/logout",
			cookies: { "sysauth_https": "expired-sid" },
			query: { "stoken": "some-token" },
			env: { HTTPS: "on" }
		};
		let res = router.handle(deps, test_config, request, {});
		assert.match(truthy(), res.ok);
		assert.match("/", res.data.headers["Location"], "Should redirect to root if session is invalid");
	});
});

it('router: security - W3: post_logout_redirect_uri match check', () => {
	let malformed_config = { ...f.MOCK_CONFIG, redirect_uri: "not-a-url" };
	let sid = "test-sid";
	let id_token = "test-id-token";

	with_context({
		fs:          { data: {} },
		ubus:        { data: {
			"session:get": { values: { token: "valid-stoken", oidc_id_token: id_token, user: "admin" } },
			"session:destroy": {}
		} },
		http_client: { data: {
			[`${f.MOCK_CONFIG.issuer_url}/.well-known/openid-configuration`]: {
				status: 200, body: { ...f.MOCK_DISCOVERY, end_session_endpoint: "https://idp.com/logout" }
			}
		} },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let request = {
			path: "/logout",
			cookies: { sysauth_https: sid },
			query: { stoken: "valid-stoken" }
		};
		let res = router.handle(deps, malformed_config, request);
		assert.match(truthy(), res.ok, "Should succeed even with malformed redirect_uri");
		let loc = res.data.headers.Location;
		assert.match(-1, index(loc, "post_logout_redirect_uri="), "Should OMIT post_logout_redirect_uri for malformed URI");
	});
});
