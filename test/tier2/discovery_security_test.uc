import { it, assert, truthy, falsy, spy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';

it('discovery: security - prevent cache poisoning on issuer mismatch (B5)', () => {
	let issuer = "https://trusted.idp";
	let evil_doc = { ...f.MOCK_DISCOVERY, issuer: "https://evil.idp" };

	with_context({
		fs:          { data: {} },
		http_client: { data: { [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: evil_doc } } },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let res = discovery.discover(deps, issuer);

		assert.match(falsy(), res.ok, "Should fail on issuer mismatch");
		assert.match("DISCOVERY_ISSUER_MISMATCH", res.error);

		let rename_calls = spy(deps.fs).calls.rename || [];
		let cache_written = false;
		for (let c in rename_calls) {
			if (match(c[1], /oidc-discovery-/)) { cache_written = true; break; }
		}
		assert.match(falsy(), cache_written, "Cache MUST NOT be written when validation fails (B5)");
	});
});

it('discovery: security - prevent cache poisoning on missing required fields', () => {
	let issuer = "https://trusted.idp";
	let broken_doc = { issuer: issuer };

	with_context({
		fs:          { data: {} },
		http_client: { data: { [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: broken_doc } } },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let res = discovery.discover(deps, issuer);
		assert.match(falsy(), res.ok);

		let rename_calls = spy(deps.fs).calls.rename || [];
		let cache_written = false;
		for (let c in rename_calls) {
			if (match(c[1], /oidc-discovery-/)) { cache_written = true; break; }
		}
		assert.match(falsy(), cache_written, "Cache MUST NOT be written for incomplete discovery doc");
	});
});

it('discovery: security - ensure sanitized logging on issuer mismatch (W4)', () => {
	let issuer = "https://trusted.idp";
	let evil_issuer = "https://evil.com/path?malicious=true";
	let evil_doc = { ...f.MOCK_DISCOVERY, issuer: evil_issuer };

	with_context({
		fs:          { data: {} },
		http_client: { data: { [`${issuer}/.well-known/openid-configuration`]: { status: 200, body: evil_doc } } },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let log_entries = [];
		deps.log = (l, m) => push(log_entries, [l, m]);

		discovery.discover(deps, issuer);

		let log_found = false;
		for (let e in log_entries) {
			log_found = true;
			assert.match(-1, index(e[1], evil_issuer), "Raw malicious issuer MUST NOT be logged");
		}
		assert.match(truthy(), log_found, "Mismatch error should have been logged");
	});
});

it('discovery: security - normalized issuer comparison (W2)', () => {
	let issuer = "https://trusted.idp/";
	let doc = { ...f.MOCK_DISCOVERY, issuer: "https://trusted.idp" };

	with_context({
		fs:          { data: {} },
		http_client: { data: { "https://trusted.idp/.well-known/openid-configuration": { status: 200, body: doc } } },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let res = discovery.discover(deps, issuer);
		assert.match(truthy(), res.ok, "Should succeed with normalized comparison");
		assert.match("https://trusted.idp", res.data.issuer);
	});
});
