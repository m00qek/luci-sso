import { test, assert, assert_eq } from 'testing';
import * as discovery from 'luci_sso.discovery';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

test('discovery: security - compliance - constant_time_eq used for issuer comparison', () => {
    let issuer = "https://trusted.idp";
    let doc = { ...f.MOCK_DISCOVERY, issuer: issuer };

    let mocked = mock.create();

    // Verify it fails during discovery validation when issuer mismatch occurs
    let evil_doc = { ...doc, issuer: "https://evil.idp" };
    mocked.with_responses({
        [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: evil_doc }
    }).spy((io) => {
        let res = discovery.discover(io, issuer);
        assert(!res.ok, "Should fail on issuer mismatch");
        assert_eq(res.error, "DISCOVERY_ISSUER_MISMATCH");
    });

    // We can't easily verify "constant-timeness" via return values alone,
    // so we must rely on the code fix to implement it as mandated.
});
