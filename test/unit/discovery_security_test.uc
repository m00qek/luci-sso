import { test, assert, assert_eq } from '../testing.uc';
import * as discovery from 'luci_sso.discovery';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';

test('discovery: security - prevent cache poisoning on issuer mismatch (B5)', () => {
    let issuer = "https://trusted.idp";
    let cache_path = `/var/run/luci-sso/oidc-discovery-extracted_later.json`;
    
    // Malicious discovery doc claiming to be evil.com
    let evil_doc = { ...f.MOCK_DISCOVERY, issuer: "https://evil.idp" };

    mock.create()
        .with_responses({
            [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: evil_doc }
        })
        .spy((io) => {
            let res = discovery.discover(io, issuer);
            
            assert(!res.ok, "Should fail on issuer mismatch");
            assert_eq(res.error, "DISCOVERY_ISSUER_MISMATCH");

            // Verify NO files were written to cache
            let files = io.lsdir("/var/run/luci-sso");
            let cache_written = false;
            for (let f in files) if (match(f, /^oidc-discovery-/)) cache_written = true;
            
            assert(!cache_written, "Cache MUST NOT be written when validation fails (B5)");
        });
});

test('discovery: security - prevent cache poisoning on missing required fields', () => {
    let issuer = "https://trusted.idp";
    let broken_doc = { issuer: issuer }; // Missing everything else

    mock.create()
        .with_responses({
            [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: broken_doc }
        })
        .spy((io) => {
            let res = discovery.discover(io, issuer);
            assert(!res.ok);
            
            let files = io.lsdir("/var/run/luci-sso");
            let cache_written = false;
            for (let f in files) if (match(f, /^oidc-discovery-/)) cache_written = true;
            
            assert(!cache_written, "Cache MUST NOT be written for incomplete discovery doc");
        });
});

test('discovery: security - ensure sanitized logging on issuer mismatch (W4)', () => {
    let issuer = "https://trusted.idp";
    let evil_issuer = "https://evil.com/path?malicious=true";
    let evil_doc = { ...f.MOCK_DISCOVERY, issuer: evil_issuer };

    let data = mock.create()
        .with_responses({
            [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: evil_doc }
        })
        .spy((io) => {
            discovery.discover(io, issuer);
        });

    // Verify raw evil_issuer is NOT in logs
    let history = data.all();
    let log_found = false;
    for (let entry in history) {
        if (entry.type == "log") {
            log_found = true;
            let msg = entry.args[1];
            assert(index(msg, evil_issuer) == -1, "Raw malicious issuer MUST NOT be logged");
        }
    }
    assert(log_found, "Mismatch error should have been logged");
});
