import { it, assert, truthy, falsy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

function make_discovery_deps(io) {
	return {
		fs: {
			readfile:  (p)    => io.read_file(p),
			writefile: (p, d) => io.write_file(p, d),
			unlink:    (p)    => io.remove(p),
			rename:    (o, n) => io.rename(o, n),
		},
		http:  { get: (url, opts) => io.http_get(url, opts) },
		clock: { time: () => io.time() },
		log: io.log
	};
}

it('discovery: security - prevent cache poisoning on issuer mismatch (B5)', () => {
    let issuer = "https://trusted.idp";
    let cache_path = `/var/run/luci-sso/oidc-discovery-extracted_later.json`;
    
    // Malicious discovery doc claiming to be evil.com
    let evil_doc = { ...f.MOCK_DISCOVERY, issuer: "https://evil.idp" };

    mock.create()
        .with_responses({
            [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: evil_doc }
        })
        .spy((io) => {
            let res = discovery.discover(make_discovery_deps(io), issuer);
            
            assert.match(falsy(), res.ok, "Should fail on issuer mismatch");
            assert.match("DISCOVERY_ISSUER_MISMATCH", res.error);

            // Verify NO files were written to cache
            let files = io.lsdir("/var/run/luci-sso");
            let cache_written = false;
            for (let f in files) if (match(f, /^oidc-discovery-/)) cache_written = true;
            
            assert.match(falsy(), cache_written, "Cache MUST NOT be written when validation fails (B5)");
        });
});

it('discovery: security - prevent cache poisoning on missing required fields', () => {
    let issuer = "https://trusted.idp";
    let broken_doc = { issuer: issuer }; // Missing everything else

    mock.create()
        .with_responses({
            [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: broken_doc }
        })
        .spy((io) => {
            let res = discovery.discover(make_discovery_deps(io), issuer);
            assert.match(falsy(), res.ok);
            
            let files = io.lsdir("/var/run/luci-sso");
            let cache_written = false;
            for (let f in files) if (match(f, /^oidc-discovery-/)) cache_written = true;
            
            assert.match(falsy(), cache_written, "Cache MUST NOT be written for incomplete discovery doc");
        });
});

it('discovery: security - ensure sanitized logging on issuer mismatch (W4)', () => {
    let issuer = "https://trusted.idp";
    let evil_issuer = "https://evil.com/path?malicious=true";
    let evil_doc = { ...f.MOCK_DISCOVERY, issuer: evil_issuer };

    let data = mock.create()
        .with_responses({
            [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: evil_doc }
        })
        .spy((io) => {
            discovery.discover(make_discovery_deps(io), issuer);
        });

    // Verify raw evil_issuer is NOT in logs
    let history = data.all();
    let log_found = false;
    for (let entry in history) {
        if (entry.type == "log") {
            log_found = true;
            let msg = entry.args[1];
            assert.match(-1, index(msg, evil_issuer), "Raw malicious issuer MUST NOT be logged");
        }
    }
    assert.match(truthy(), log_found, "Mismatch error should have been logged");
});

it('discovery: security - normalized issuer comparison (W2)', () => {
    let issuer = "https://trusted.idp/"; // Trailing slash
    let doc = { ...f.MOCK_DISCOVERY, issuer: "https://trusted.idp" }; // No trailing slash

    mock.create()
        .with_responses({
            [`https://trusted.idp/.well-known/openid-configuration`]: { status: 200, body: doc }
        })
        .spy((io) => {
            let res = discovery.discover(make_discovery_deps(io), issuer);
            assert.match(truthy(), res.ok, "Should succeed with normalized comparison");
            assert.match("https://trusted.idp", res.data.issuer);
        });
});
