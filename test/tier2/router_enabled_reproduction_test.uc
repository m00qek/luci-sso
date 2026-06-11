import { it, assert, truthy, falsy } from 'utest';
import * as config_loader from 'luci_sso.config';
import * as web_mod from 'luci_sso.web';
import * as router from 'luci_sso.router';
import { with_context } from 'context';

it('router: reproduction - enabled endpoint returns JSON even if disabled (W2)', () => {
	let mock_uci = {
		"luci-sso": {
			"default": { ".type": "oidc", "enabled": "0" }
		}
	};

	with_context({
		fs:    { data: {} },
		uci:   { data: mock_uci },
		clock: { data: { now: 1516239022 } }
	}, (deps) => {
		let getenv = (k) => {
			let env = { PATH_INFO: "/", QUERY_STRING: "action=enabled", HTTP_HOST: "luci.test" };
			return env[k] || null;
		};

		let res_req = web_mod.request({ getenv });
		assert.match(truthy(), res_req.ok);
		let req = res_req.data;

		let res_c = config_loader.load({ uci: deps.uci, log: deps.log });
		assert.match(falsy(), res_c.ok);
		assert.match("SSO_DISABLED", res_c.error);

		let res_router = router.handle(deps, null, req);
		assert.match(truthy(), res_router.ok, "Action 'enabled' MUST succeed even without config");
		assert.match(200, res_router.data.status);
		assert.match('{"enabled": false}', res_router.data.body);
	});
});

it('router: security - null config guard (B2)', () => {
	with_context({
		fs:    { data: {} },
		uci:   { data: {} },
		clock: { data: { now: 1516239022 } }
	}, (deps) => {
		let req = { path: "/", query: {}, cookies: {}, headers: {} };
		let res = router.handle(deps, null, req);
		assert.match(falsy(), res.ok, "Should fail when config is null");
		assert.match("SSO_DISABLED", res.error);
		assert.match(503, res.details.http_status);
	});
});
