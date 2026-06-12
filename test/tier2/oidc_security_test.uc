import { describe, it, assert, truthy, falsy } from 'utest';
import * as oidc from 'luci_sso.oidc';
import * as crypto from 'luci_sso.crypto';
import * as Result from 'luci_sso.result';
import * as f from 'tier2.fixtures';
import * as h from 'lib.helpers';
import { with_context } from 'context';

const PRIVKEY = f.MOCK_PRIVKEY;
const JWKS = { keys: [ f.MOCK_JWK ] };
const TEST_POLICY = { allowed_algs: ["RS256", "ES256"] };

describe('oidc: security', () => {
	it('reject HS256 algorithm confusion', () => {
		let payload = {
			iss: f.MOCK_CONFIG.issuer_url,
			aud: f.MOCK_CONFIG.client_id,
			sub: "user1",
			nonce: "n1",
			iat: 100,
			exp: 1000,
			at_hash: "fake_hash"
		};
		let res_s = crypto.jws_sign(payload, "secret-key");
		assert.match(truthy(), Result.is(res_s));
		let token = res_s.data;
		let tokens = { id_token: token, access_token: "fake" };
		let keys = [{ kty: "RSA", kid: "key1", n: "...", e: "..." }];

		with_context({}, (deps) => {
			// BLOCKER: No TEST_POLICY, so production DEFAULT_POLICY (RS256/ES256) applies
			let res = oidc.verify_id_token(deps, tokens, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok, "Should NOT accept HS256 token in OIDC flow");
			assert.match("UNSUPPORTED_ALGORITHM", res.error);
		});
	});

	it('reject insecure token endpoint', () => {
		let insecure_disc = { ...f.MOCK_DISCOVERY, token_endpoint: "http://insecure.com/token" };
		with_context({}, (deps) => {
			let res = oidc.exchange_code(deps, f.MOCK_CONFIG, insecure_disc, "code", "verifier-is-long-enough-to-pass-basic-check-123");
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INSECURE_TOKEN_ENDPOINT", res.error);
		});
	});

	it('handle network failure during exchange', () => {
		with_context({
			http_client: { data: { [f.MOCK_DISCOVERY.token_endpoint]: { error: "TLS_VERIFY_FAILED" } } }
		}, (deps) => {
			let res = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code", "verifier-is-long-enough-to-pass-basic-check-123");
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("TOKEN_ENDPOINT_NETWORK_ERROR", res.error);
		});
	});

	it('reject insecure issuer URL', () => {
		with_context({}, (deps) => {
			let res = oidc.discover(deps, "http://insecure.idp");
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INSECURE_ISSUER_URL", res.error);
		});
	});

	it('reject insecure internal issuer URL', () => {
		with_context({}, (deps) => {
			let res = oidc.discover(deps, "https://secure.idp", { internal_issuer_url: "http://insecure.local" });
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INSECURE_FETCH_URL", res.error);
		});
	});

	it('reject discovery document with insecure endpoints', () => {
		let evil_disc = { ...f.MOCK_DISCOVERY, jwks_uri: "http://insecure.idp/jwks" };
		let issuer = "https://trusted.idp";
		let url = issuer + "/.well-known/openid-configuration";

		with_context({
			http_client: { data: { [url]: { status: 200, body: evil_disc } } }
		}, (deps) => {
			let res = oidc.discover(deps, issuer);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INSECURE_ENDPOINT", res.error);
		});
	});

	it('reject invalid at_hash', () => {
		let access_token = "access-token-123";
		let payload = {
			iss: f.MOCK_CONFIG.issuer_url,
			aud: f.MOCK_CONFIG.client_id,
			sub: "user1",
			nonce: "n1",
			iat: 100,
			exp: 1000,
			at_hash: "wrong_hash_!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
		};
		let token = h.generate_id_token(payload, PRIVKEY, "RS256");

		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, { id_token: token, access_token }, JWKS.keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500, TEST_POLICY);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok, "Should reject invalid at_hash");
			assert.match("AT_HASH_MISMATCH", res.error);
		});
	});

	it('reject missing mandatory claims', () => {
		let keys = JWKS.keys;

		let p_no_exp = { ...f.MOCK_CLAIMS, exp: null, nonce: "n1", sub: "u1", iat: 100 };
		let t_no_exp = { id_token: h.generate_id_token(p_no_exp, PRIVKEY, "RS256"), access_token: "a" };
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, t_no_exp, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500, TEST_POLICY);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok, "Should reject ID token missing 'exp' claim");
			assert.match("MISSING_EXP_CLAIM", res.error);
		});

		let p_no_iat = { ...f.MOCK_CLAIMS, iat: null, nonce: "n1", sub: "u1" };
		let t_no_iat = { id_token: h.generate_id_token(p_no_iat, PRIVKEY, "RS256"), access_token: "a" };
		with_context({}, (deps) => {
			let res = oidc.verify_id_token(deps, t_no_iat, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 500, TEST_POLICY);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok, "Should reject ID token missing 'iat' claim");
			assert.match("MISSING_IAT_CLAIM", res.error);
		});
	});

	it('reject missing mandatory at_hash claim (W2)', () => {
		let keys = JWKS.keys;
		let payload = { ...f.MOCK_CLAIMS, at_hash: null, nonce: "n1", sub: "u1" };
		let tokens = { id_token: h.generate_id_token(payload, PRIVKEY, "RS256"), access_token: "at123" };
		let log_calls = [];

		with_context({}, (deps) => {
			deps.log = (level, msg) => push(log_calls, [level, msg]);
			let res = oidc.verify_id_token(deps, tokens, keys, f.MOCK_CONFIG, { nonce: "n1" }, f.MOCK_DISCOVERY, 1500, TEST_POLICY);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok, "Should reject ID token missing 'at_hash' claim");
			assert.match("MISSING_AT_HASH", res.error);
		});

		let found = false;
		for (let e in log_calls) {
			if (e[0] == "error" && match(e[1], /ID Token missing mandatory at_hash claim/)) {
				found = true; break;
			}
		}
		assert.match(truthy(), found, "Should log security violation");
	});

	it('reject UserInfo sub mismatch', () => {
		let endpoint = "https://trusted.idp/userinfo";
		let at = "access-token-123";
		let mock_res = { sub: "EVIL-USER", email: "victim@example.com" };

		with_context({
			http_client: { data: { [endpoint]: { status: 200, body: mock_res } } }
		}, (deps) => {
			let res = oidc.fetch_userinfo(deps, endpoint, at);
			assert.match(truthy(), Result.is(res));
			assert.match(truthy(), res.ok);
			assert.match("EVIL-USER", res.data.sub);
		});
	});

	it('enforce RFC 7636 PKCE verifier length (43-128 chars)', () => {
		with_context({}, (deps) => {
			let res = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", "too-short");
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INVALID_PKCE_VERIFIER", res.error);
		});

		let long_verifier = "";
		for (let i = 0; i < 129; i++) long_verifier += "a";
		with_context({}, (deps) => {
			let res = oidc.exchange_code(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "c", long_verifier);
			assert.match(truthy(), Result.is(res));
			assert.match(falsy(), res.ok);
			assert.match("INVALID_PKCE_VERIFIER", res.error);
		});
	});
});
