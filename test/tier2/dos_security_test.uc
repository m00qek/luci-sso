import { test, assert, assert_eq } from 'testing';
import * as oidc from 'luci_sso.oidc';
import * as handshake from 'luci_sso.handshake';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

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

test('handshake: security - register_token deferred until after verification (DoS prevention)', () => {
    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: f.MOCK_CONFIG.issuer_url,
        redirect_uri: "https://r/c",
        roles: [{ name: "admin", emails: ["user-123"], read: ["*"], write: ["*"] }]
    };

    mock.create()
        .with_env({}, (io) => {
            // 1. Setup mock responses: Successful exchange, but verification will fail later
            io.http_get = (url) => ({ status: 200, body: { read: () => sprintf("%J", f.MOCK_DISCOVERY) } });
            io.http_post = (url) => ({ status: 200, body: { read: () => sprintf("%J", { access_token: "at1", id_token: "invalid.id.token" }) } });

            // 2. Setup state
            let state_res = handshake.initiate(io, test_config);
            let state_val = replace(state_res.data.url, /^.*state=([^&]+).*$/, "$1");
            let request = {
                path: "/callback",
                query: { code: "c1", state: state_val },
                cookies: { "__Host-luci_sso_state": state_res.data.token },
                env: { HTTPS: "on" }
            };

            // 3. This call should fail because id_token is invalid
            let auth_res = handshake.authenticate(io, test_config, request, { allowed_algs: ["RS256"] });
            assert(!auth_res.ok, "Authentication should fail due to invalid ID token");

            // 4. Verify that register_token was NEVER called
            let history = io.__state__.history;
            let registered = false;
            for (let e in history) {
                if (e.type == "ubus" && e.args[1] == "register_token") {
                    registered = true;
                    break;
                }
            }
            assert(!registered, "Should NOT register token before successful ID token verification");
        });
});
