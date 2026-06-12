import { it, assert, truthy, falsy } from 'utest';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

it('handshake: security - DO NOT retry JWKS refresh if kid is missing', () => {
    let access_token = "access-token-123";
    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: f.MOCK_CONFIG.issuer_url,
        redirect_uri: "https://r/c",
    };

    let jwks_uri = f.MOCK_DISCOVERY.jwks_uri;
    let jwks = { keys: [ f.MOCK_JWK ] };
    let call_count = 0;
    // Token is built lazily after session.create_state reveals the nonce
    let pending_tokens = { access_token: null, id_token: null };

    with_context({
        fs:    { data: { "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" } },
        http_client: {
            behavior: {
                get: (url, opts) => {
                    if (url == f.MOCK_DISCOVERY.issuer + "/.well-known/openid-configuration")
                        return { ok: true, data: { status: 200, body: sprintf("%J", f.MOCK_DISCOVERY) } };
                    if (url == jwks_uri) {
                        call_count++;
                        return { ok: true, data: { status: 200, body: sprintf("%J", jwks) } };
                    }
                    return { ok: false, error: "HTTP_REQUEST_FAILED", detail: "NOT_FOUND" };
                },
                post: (url, opts) => {
                    return { ok: true, data: { status: 200, body: sprintf("%J", pending_tokens) } };
                }
            }
        },
        clock: { data: { now: 1516239022 } }
    }, (deps) => {
        let state_res = session.create_state(deps);
        assert.match(truthy(), state_res.ok);
        let s_data = state_res.data;

        // Build ID token with the real nonce but signed with an unknown key and no kid
        let payload = { ...f.MOCK_CLAIMS, nonce: s_data.nonce };
        pending_tokens.access_token = access_token;
        pending_tokens.id_token = h.generate_id_token(payload, f.ROTATION_NEW_PRIVKEY, "RS256", null);

        let request = {
            query: { code: "c1", state: s_data.state },
            cookies: { "__Host-luci_sso_state": s_data.token }
        };

        let res = handshake.authenticate(deps, test_config, request);
        assert.match(falsy(), res.ok, "Handshake should fail due to invalid signature");
        assert.match("ID_TOKEN_VERIFICATION_FAILED", res.error);
        assert.match("INVALID_SIGNATURE", res.details?.details);
        assert.match(1, call_count, "JWKS should have been fetched exactly once (no retry when kid is missing)");
    });
});
