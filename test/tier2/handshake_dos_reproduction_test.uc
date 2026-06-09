import { it, assert, truthy, falsy } from 'utest';
import * as Result from 'luci_sso.result';
import * as handshake from 'luci_sso.handshake';
import * as session from 'luci_sso.session';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

function make_session_deps(io) {
	return {
		fs: {
			readfile:  (p)    => io.read_file(p),
			writefile: (p, d) => io.write_file(p, d),
			mkdir:     (p, m) => io.mkdir(p, m),
			unlink:    (p)    => io.remove(p),
			rename:    (o, n) => io.rename(o, n),
			stat:      (p)    => io.stat(p),
			chmod:     (p, m) => io.chmod(p, m),
			lsdir:     (p)    => io.lsdir(p),
			error:     ()     => io.fserror()
		},
		clock: { time: () => io.time(), sleep: (s) => io.sleep(s) },
		log: io.log
	};
}

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
    
    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_uci({
            "luci-sso": {
                "default": { ...test_config, ".type": "oidc", "enabled": "1" }
            }
        })
        .spy((io) => {
            io.http_get = (url) => {
                if (url == f.MOCK_DISCOVERY.issuer + "/.well-known/openid-configuration") {
                    return Result.ok({ status: 200, body: { read: () => sprintf("%J", f.MOCK_DISCOVERY) } });
                } else if (url == jwks_uri) {
                    call_count++;
                    return Result.ok({ status: 200, body: { read: () => sprintf("%J", jwks) } });
                }
                return Result.ok({ status: 404, body: { read: () => "" } });
            };

            // Create a valid handshake state
            let state_res = session.create_state(make_session_deps(io));
            assert.match(truthy(), state_res.ok);
            let s_data = state_res.data;

            // Create ID token WITHOUT kid
            let payload = { 
                ...f.MOCK_CLAIMS,
                nonce: s_data.nonce
            };
            // Generate token with a different key to ensure signature failure
            let token = h.generate_id_token(payload, f.ROTATION_NEW_PRIVKEY, "RS256", null); // Passing null for kid
            let tokens = { access_token: access_token, id_token: token };

            io.http_post = (url) => Result.ok({ 
                status: 200, 
                body: { read: () => sprintf("%J", tokens) } 
            });

            let request = {
                path: "/callback",
                query: { code: "c1", state: s_data.state },
                cookies: { "__Host-luci_sso_state": s_data.token },
                env: { HTTPS: "on" }
            };

            // This should NOT trigger the rotation recovery path because kid is missing
            let res = handshake.authenticate(io, test_config, request);
            
            assert.match(falsy(), res.ok, "Handshake should fail due to invalid signature");
            assert.match("ID_TOKEN_VERIFICATION_FAILED", res.error);
            assert.match("INVALID_SIGNATURE", res.details?.details);
            assert.match(1, call_count, "JWKS should have been fetched exactly once (no retry should occur if kid is missing)");
        });
});
