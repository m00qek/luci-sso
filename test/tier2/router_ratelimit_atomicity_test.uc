import { it, assert, truthy } from 'utest';
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

it('router: rate limit persistence is atomic', () => {
    let test_config = {
        ...f.MOCK_CONFIG,
        enabled: "1"
    };

    let factory = mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_responses({
            [f.MOCK_CONFIG.issuer_url + "/.well-known/openid-configuration"]: { status: 200, body: f.MOCK_DISCOVERY }
        });

    let history = factory.spy((io) => {
        let request = { path: "/", query: {}, cookies: {} };
        router.handle(make_router_deps(io), test_config, request);
    });

    // Check if rename was called for the ratelimit file
    // The path in router.uc is /var/run/luci-sso/ratelimit.json
    const RATELIMIT_FILE = "/var/run/luci-sso/ratelimit.json";
    const TMP_FILE = RATELIMIT_FILE + ".tmp";

    assert.match(truthy(), history.called("write_file", TMP_FILE), "Should write to temporary file first");
    assert.match(truthy(), history.called("rename", TMP_FILE, RATELIMIT_FILE), "Should atomically rename tmp to target");
});
