import { it, assert, truthy, falsy } from 'utest';
import * as Result from 'luci_sso.result';
import * as handshake from 'luci_sso.handshake';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';

function make_handshake_deps(io) {
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
		http:  { get: (url, opts) => io.http_get(url, opts), post: (url, opts) => io.http_post(url, opts) },
		ubus:  { call: (obj, method, args) => io.ubus_call(obj, method, args) },
		clock: { time: () => io.time(), sleep: (s) => io.sleep(s) },
		log:   io.log
	};
}

it('handshake: warning - log warning for long-lived access tokens (W2)', () => {
    let now = 1516239022;
    // Lifetime = 25 hours (90000 seconds) > 24 hours (86400)
    let payload = { iat: now, exp: now + 90000 };
    let long_lived_token = "header." + encoding.b64url_encode(sprintf("%J", payload)).data + ".signature";
    
    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: f.MOCK_CONFIG.issuer_url,
        redirect_uri: "https://r/c",
        roles: [{ name: "admin", emails: ["user-123"], read: ["*"], write: ["*"] }]
    };

    let tokens = { access_token: long_lived_token, id_token: "" };

    mock.create()
        .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
        .with_ubus({ 
            "session:create": { "ubus_rpc_session": "s1" }, 
            "session:grant": {},
            "session:set": {} 
        })
        .spy((io) => {
            io.http_get = (url) => {
                if (index(url, "jwks") != -1) return Result.ok({ status: 200, body: { read: () => sprintf("%J", { keys: [ f.MOCK_JWK ] }) } });
                return Result.ok({ status: 200, body: { read: () => sprintf("%J", f.MOCK_DISCOVERY) } });
            };

            let state_res = handshake.initiate(make_handshake_deps(io), test_config);
            assert.match(truthy(), state_res.ok, `initiate failed: ${state_res.error}`);

            let state_val = replace(state_res.data.url, /^.*state=([^&]+).*$/, "$1");
            let nonce_val = replace(state_res.data.url, /^.*nonce=([^&]+).*$/, "$1");

            // Setup minimal environment
            let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(tokens.access_token).data, 0, 16)).data;
            let id_payload = { ...f.MOCK_CLAIMS, sub: "user-123", email: "user-123", nonce: nonce_val, at_hash: at_hash };
            tokens.id_token = h.generate_id_token(id_payload, f.MOCK_PRIVKEY, "RS256");

            io.http_post = (url) => Result.ok({ status: 200, body: { read: () => sprintf("%J", tokens) } });

            let request = {
                path: "/callback",
                query: { code: "c1", state: state_val },
                cookies: { "__Host-luci_sso_state": state_res.data.token },
                env: { HTTPS: "on" }
            };

            let auth_res = handshake.authenticate(make_handshake_deps(io), test_config, request);
            assert.match(truthy(), auth_res.ok, `authenticate failed: ${auth_res.error} ${auth_res.details}`);

            // Manual iteration check
            let found = false;
            for (let e in io.__state__.history) {
                if (e.type == "log" && e.args[0] == "warn" && match(e.args[1], /Access token lifetime exceeds 24h replay window/)) {
                    found = true;
                    break;
                }
            }
            assert.match(truthy(), found, "Should log warning for long-lived access token");
        });
});

it('handshake: warning - silent for opaque or short-lived tokens', () => {
    let test_config = {
        ...f.MOCK_CONFIG,
        internal_issuer_url: f.MOCK_CONFIG.issuer_url,
        redirect_uri: "https://r/c",
        roles: [{ name: "admin", emails: ["user-123"], read: ["*"], write: ["*"] }]
    };

    let cases = [
        { name: "Opaque", token: "opaque_string_without_dots" },
        { name: "Short-lived", token: "h." + encoding.b64url_encode(sprintf("%J", { iat: 100, exp: 200 })).data + ".s" }
    ];

    for (let c in cases) {
        let tokens = { access_token: c.token, id_token: "" };
        mock.create()
            .with_files({ "/etc/luci-sso/secret.key": "fixed-test-secret-32-bytes-!!!!" })
            .with_ubus({ 
                "session:create": { "ubus_rpc_session": "s1" }, 
                "session:grant": {},
                "session:set": {} 
            })
            .spy((io) => {
                io.http_get = (url) => {
                    if (index(url, "jwks") != -1) return Result.ok({ status: 200, body: { read: () => sprintf("%J", { keys: [ f.MOCK_JWK ] }) } });
                    return Result.ok({ status: 200, body: { read: () => sprintf("%J", f.MOCK_DISCOVERY) } });
                };

                let state_res = handshake.initiate(make_handshake_deps(io), test_config);
                assert.match(truthy(), state_res.ok, `initiate failed: ${state_res.error}`);

                let state_val = replace(state_res.data.url, /^.*state=([^&]+).*$/, "$1");
                let nonce_val = replace(state_res.data.url, /^.*nonce=([^&]+).*$/, "$1");

                let at_hash = encoding.b64url_encode(substr(crypto.hash_sha256(tokens.access_token).data, 0, 16)).data;
                let id_payload = { ...f.MOCK_CLAIMS, sub: "user-123", email: "user-123", nonce: nonce_val, at_hash: at_hash };
                tokens.id_token = h.generate_id_token(id_payload, f.MOCK_PRIVKEY, "RS256");
                
                io.http_post = (url) => Result.ok({ status: 200, body: { read: () => sprintf("%J", tokens) } });

                let request = {
                    path: "/callback",
                    query: { code: "c1", state: state_val },
                    cookies: { "__Host-luci_sso_state": state_res.data.token },
                    env: { HTTPS: "on" }
                };

                let auth_res = handshake.authenticate(make_handshake_deps(io), test_config, request);
                assert.match(truthy(), auth_res.ok, `authenticate failed: ${auth_res.error} ${auth_res.details}`);

                let found = false;
                for (let e in io.__state__.history) {
                    if (e.type == "log" && e.args[0] == "warn" && match(e.args[1], /Access token lifetime exceeds 24h replay window/)) {
                        found = true;
                        break;
                    }
                }
                assert.match(falsy(), found, `Should NOT log warning for ${c.name} token`);
            });
    }
});
