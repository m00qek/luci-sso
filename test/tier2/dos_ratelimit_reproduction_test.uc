import { it, assert, truthy, falsy } from 'utest';
import * as router from 'luci_sso.router';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

function make_router_deps(io) {
	return {
		fs: {
			readfile:  (p)    => io.read_file(p),
			writefile: (p, d) => io.write_file(p, d),
			mkdir:     (p, m) => io.mkdir(p, m),
			unlink:    (p)    => io.remove(p),
			rename:    (o, n) => io.rename(o, n),
			stat:      (p)    => io.stat(p),
			chmod:     (p, m) => io.chmod(p, m),
			lsdir:     (p)    => io.lsdir(p),
			error:     ()     => io.fserror()
		},
		http:  { get: (url, opts) => io.http_get(url, opts), post: (url, opts) => io.http_post(url, opts) },
		ubus:  { call: (obj, method, args) => io.ubus_call(obj, method, args) },
		uci:   io.uci_cursor(),
		clock: { time: () => io.time(), sleep: (s) => io.sleep(s) },
		log:   io.log
	};
}

it('router: reproduction - lacks global rate limiting', () => {
    let test_config = {
        ...f.MOCK_CONFIG,
        enabled: "1"
    };

    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_responses({
            [f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY }
        })
        .spy((io) => {
            let request = { path: "/", query: {}, cookies: {} };
            
            // 1. Verify Rate Limiting for Handshake Initiation
            // We need to freeze time because the mock increments it on EVERY trackable call (read_file, log, etc)
            let fixed_time = io.time();
            io.time = () => fixed_time;

            for (let i = 1; i <= 60; i++) {
                let res = router.handle(make_router_deps(io), test_config, request);
                if (i <= 50) {
                    assert.match(truthy(), res.ok, `Request ${i} SHOULD succeed (within limit)`);
                } else {
                    assert.match(falsy(), res.ok, `Request ${i} SHOULD fail (exceeded limit)`);
                    assert.match("TOO_MANY_REQUESTS", res.error);
                }
            }

            // 2. Verify Exemption for Action=Enabled (N3 Hardening)
            // (Note: The window is still 60s, so we're already past the threshold)
            let action_req = { path: "/", query: { action: "enabled" }, cookies: {} };
            for (let i = 0; i < 5; i++) {
                let res = router.handle(make_router_deps(io), test_config, action_req);
                assert.match(truthy(), res.ok, "Action=Enabled SHOULD be exempt from rate limiting to prevent UI DoS (N3)");
                assert.match(200, res.data.status);
            }
        });
});
