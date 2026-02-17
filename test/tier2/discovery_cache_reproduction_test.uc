import { test, assert, assert_eq } from 'testing';
import * as discovery from 'luci_sso.discovery';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

test('discovery: reproduction - case-insensitive cache miss (W6)', () => {
    let issuer_upper = "HTTPS://TRUSTED.IDP";
    let issuer_lower = "https://trusted.idp";
    let doc = { ...f.MOCK_DISCOVERY, issuer: issuer_lower };

    let factory = mock.create();
    
    // 1. Warm cache with lowercase
    factory.with_responses({
        [`${issuer_lower}/.well-known/openid-configuration`]: { status: 200, body: doc }
    }).spy((io) => {
        let res1 = discovery.discover(io, issuer_lower);
        assert(res1.ok);

        // Clear responses to ensure cache is used
        io._responses = {};

        // 2. Fetch with uppercase (Should hit cache)
        let res2 = discovery.discover(io, issuer_upper);
        
        if (!res2.ok) {
            print(`DEBUG: res2 failed. error=${res2.error}, details=${res2.details}\n`);
            print(`DEBUG: history=${sprintf("%J", io.__state__.history)}\n`);
        }
        
        assert(res2.ok, "Should hit cache using normalized comparison (W6)");
    });
});
