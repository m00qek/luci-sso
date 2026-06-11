import { it, assert, truthy, spy } from 'utest';
import * as router from 'luci_sso.router';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';

it('router: rate limit persistence is atomic', () => {
	let test_config = { ...f.MOCK_CONFIG, enabled: "1" };

	const RATELIMIT_FILE = "/var/run/luci-sso/ratelimit.json";
	const TMP_FILE = RATELIMIT_FILE + ".tmp";

	let writefile_calls = null;
	let rename_calls = null;

	with_context({
		fs:          { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
		ubus:        { data: {} },
		http_client: { data: {
			[f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY }
		} },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let request = { path: "/", query: {}, cookies: {} };
		router.handle(deps, test_config, request);
		writefile_calls = spy(deps.fs).calls.writefile || [];
		rename_calls    = spy(deps.fs).calls.rename    || [];
	});

	let wrote_tmp = false;
	for (let c in writefile_calls) {
		if (c[0] === TMP_FILE) { wrote_tmp = true; break; }
	}
	assert.match(truthy(), wrote_tmp, "Should write to temporary file first");

	let renamed = false;
	for (let c in rename_calls) {
		if (c[0] === TMP_FILE && c[1] === RATELIMIT_FILE) { renamed = true; break; }
	}
	assert.match(truthy(), renamed, "Should atomically rename tmp to target");
});
