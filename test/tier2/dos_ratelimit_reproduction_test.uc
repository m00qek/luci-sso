import { test, assert, assert_eq } from 'testing';
import * as router from 'luci_sso.router';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

test('REPRODUCTION: router: lacks global rate limiting', () => {
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
                let res = router.handle(io, test_config, request);
                if (i <= 50) {
                    assert(res.ok, `Request ${i} SHOULD succeed (within limit)`);
                } else {
                    assert(!res.ok, `Request ${i} SHOULD fail (exceeded limit)`);
                    assert_eq(res.error, "TOO_MANY_REQUESTS");
                }
            }

            // 2. Verify Exemption for Action=Enabled
            // (Note: The window is still 60s, so we're already past the threshold)
            let action_req = { path: "/", query: { action: "enabled" }, cookies: {} };
            for (let i = 0; i < 5; i++) {
                let res = router.handle(io, test_config, action_req);
                assert(res.ok, "Action=Enabled SHOULD be exempt from rate limiting");
            }
        });
});
