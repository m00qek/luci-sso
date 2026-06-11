import { it, assert, truthy, falsy } from 'utest';
import * as router from 'luci_sso.router';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';

it('router: reproduction - lacks global rate limiting', () => {
	let test_config = { ...f.MOCK_CONFIG, enabled: "1" };

	with_context({
		fs:          { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
		uci:         { data: { "luci-sso": { "default": { ".type": "oidc", "enabled": "0" } } } },
		ubus:        { data: {} },
		http_client: { data: {
			[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY }
		} },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let request = { path: "/", query: {}, cookies: {} };

		// 1. Verify Rate Limiting for Handshake Initiation
		for (let i = 1; i <= 60; i++) {
			let res = router.handle(deps, test_config, request);
			if (i <= 50) {
				assert.match(truthy(), res.ok, `Request ${i} SHOULD succeed (within limit)`);
			} else {
				assert.match(falsy(), res.ok, `Request ${i} SHOULD fail (exceeded limit)`);
				assert.match("TOO_MANY_REQUESTS", res.error);
			}
		}

		// 2. Verify Exemption for Action=Enabled (N3 Hardening)
		let action_req = { path: "/", query: { action: "enabled" }, cookies: {} };
		for (let i = 0; i < 5; i++) {
			let res = router.handle(deps, test_config, action_req);
			assert.match(truthy(), res.ok, "Action=Enabled SHOULD be exempt from rate limiting to prevent UI DoS (N3)");
			assert.match(200, res.data.status);
		}
	});
});
