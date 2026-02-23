import { test, assert, assert_eq } from 'testing';
import * as router from 'luci_sso.router';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

test('router: rate limit persistence is atomic', () => {
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
        router.handle(io, test_config, request);
    });

    // Check if rename was called for the ratelimit file
    // The path in router.uc is /var/run/luci-sso/ratelimit.json
    const RATELIMIT_FILE = "/var/run/luci-sso/ratelimit.json";
    const TMP_FILE = RATELIMIT_FILE + ".tmp";

    assert(history.called("write_file", TMP_FILE), "Should write to temporary file first");
    assert(history.called("rename", TMP_FILE, RATELIMIT_FILE), "Should atomically rename tmp to target");
});
