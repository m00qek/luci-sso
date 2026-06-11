import { it, assert, truthy, spy } from 'utest';
import * as discovery from 'luci_sso.discovery';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';

it('discovery: reproduction - case-insensitive cache miss (W6)', () => {
	let issuer_upper = "HTTPS://TRUSTED.IDP";
	let issuer_lower = "https://trusted.idp";
	let doc = { ...f.MOCK_DISCOVERY, issuer: issuer_lower };

	with_context({
		fs:          { data: {} },
		http_client: { data: { [`${issuer_lower}/.well-known/openid-configuration`]: { status: 200, body: doc } } },
		clock:       { data: { now: 1516239022 } }
	}, (deps) => {
		let res1 = discovery.discover(deps, issuer_lower);
		assert.match(truthy(), res1.ok);

		let res2 = discovery.discover(deps, issuer_upper);

		if (!res2.ok) {
			print(`DEBUG: res2 failed. error=${res2.error}, details=${res2.details}\n`);
		}

		assert.match(truthy(), res2.ok, "Should hit cache using normalized comparison (W6)");

		// Cache was used for the second call — only one HTTP GET
		assert.match(1, length(spy(deps.http).calls.get));
	});
});
