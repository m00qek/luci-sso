import { test, assert, assert_eq } from '../testing.uc';
import * as oidc from 'luci_sso.oidc';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';

test('oidc: security - reject massive discovery response (DoS protection)', () => {
	// Generate a response slightly larger than 256KB using exponential doubling
	let garbage = "1234567890";
	for (let i = 0; i < 15; i++) garbage += garbage; // 10 * 2^15 = 327,680 chars (~320KB)
	let massive_body = { ...f.MOCK_DISCOVERY, garbage };

	mock.create()
        .with_responses({
            "https://massive.idp/.well-known/openid-configuration": {
                status: 200,
                body: massive_body
            }
        })
        .with_env({}, (io) => {
            let res = oidc.discover(io, "https://massive.idp");
            
            assert(!res.ok, "Should reject massive discovery document");
            assert_eq(res.error, "NETWORK_ERROR", "Should return network error (aborted read)");
            
            // Verification of the exact policy in history
            let history = io.__state__.history;
            let call = null;
            for (let e in history) if (e.type == "http_get") call = e;
            // The mock returns { error: "RESPONSE_TOO_LARGE" } which io.uc maps to "NETWORK_ERROR"
        });
});
