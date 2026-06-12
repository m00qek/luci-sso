import { describe, it, assert, truthy, falsy } from 'utest';
import * as encoding from 'luci_sso.encoding';
import * as crypto from 'luci_sso.crypto';
import * as session from 'luci_sso.session';
import * as ubus from 'luci_sso.ubus';
import * as Result from 'luci_sso.result';
import { with_context } from 'context';

describe('security: JWT', () => {
	it('reject alg: none', () => {
		let none_header = encoding.b64url_encode(sprintf("%J", { alg: "none", typ: "JWT" })).data;
		let payload = encoding.b64url_encode(sprintf("%J", { sub: "admin" })).data;
		let token = none_header + "." + payload + ".";

		let res1 = crypto.jwt_verify(token, "secret", { alg: "RS256", now: 123, clock_tolerance: 300, iss: "https://example.com", aud: "client" });
		assert.match(truthy(), Result.is(res1));
		assert.match("ALGORITHM_MISMATCH", res1.error);

		let res2 = crypto.jws_verify(token, "secret");
		assert.match(truthy(), Result.is(res2));
		assert.match("UNSUPPORTED_ALGORITHM", res2.error);
	});

	it('reject stripped signature', () => {
		let header = encoding.b64url_encode(sprintf("%J", { alg: "HS256" })).data;
		let payload = encoding.b64url_encode(sprintf("%J", { sub: "admin" })).data;
		let stripped = header + "." + payload + ".";

		let res = crypto.jwt_verify(stripped, "secret", { alg: "HS256", now: 123, clock_tolerance: 300, iss: "https://example.com", aud: "client" });
		assert.match(truthy(), Result.is(res));
		assert.match("INVALID_SIGNATURE_ENCODING", res.error);
	});

	it('payload integrity', () => {
		let secret = "secret";
		let res_s = crypto.jws_sign({foo: "bar"}, secret);
		assert.match(truthy(), Result.is(res_s));
		assert.match(truthy(), res_s.ok);
		let good_token = res_s.data;
		let parts = split(good_token, ".");

		let bad_payload = encoding.b64url_encode("{ invalid json }").data;
		let tampered = parts[0] + "." + bad_payload + "." + parts[2];

		let res = crypto.jws_verify(tampered, secret);
		assert.match(truthy(), Result.is(res));
		assert.match("INVALID_SIGNATURE", res.error, "Tampering must invalidate HMAC signature");
	});
});

describe('security: PII', () => {
	it('ensure logs never contain raw identifiers', () => {
		let user_data = {
			sub: "123456789",
			email: "attacker@evil.com",
			name: "Evil Attacker"
		};
		let log_calls = [];

		with_context({
			fs: { data: { "/etc/luci-sso/secret.key": "01234567890123456789012345678901" } },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			deps.log = (level, msg) => push(log_calls, [level, msg]);
			session.create(deps, user_data);
		});

		for (let call in log_calls) {
			let msg = call[1];
			assert.match(falsy(), match(msg, /@/), `Security Violation: Raw email found in logs: ${msg}`);
			assert.match(falsy(), match(msg, /Evil Attacker/), `Security Violation: Raw name found in logs: ${msg}`);
		}
	});
});

describe('security: token registry', () => {
	it('cleanup of stale tokens', () => {
		let now = 1516239022;
		let old_token_path = "/var/run/luci-sso/tokens/old-id";
		let new_token_path = "/var/run/luci-sso/tokens/new-id";

		with_context({
			fs: {
				data: {
					[old_token_path]: { ".type": "directory" },
					[new_token_path]: { ".type": "directory" }
				},
				behavior: {
					stat: (path) => {
						if (index(path, "old") > 0) return { mtime: now - 90000 };
						return { mtime: now };
					}
				}
			},
			clock: { data: { now: now } }
		}, (deps) => {
			let res = ubus.reap_stale_tokens(deps);
			assert.match(truthy(), res.ok);
			assert.match(1, res.data, "Should report 1 token reaped");

			let files = deps.fs.lsdir("/var/run/luci-sso/tokens");
			assert.match(-1, index(files, "old-id"), "Old token should be reaped");
			assert.match(truthy(), index(files, "new-id") >= 0, "New token should remain");
		});
	});
});

describe('security: handshake registry', () => {
	it('cleanup of stale handshakes (N5)', () => {
		let now = 1516239022;
		let old_h_path = "/var/run/luci-sso/handshake_old.json";
		let new_h_path = "/var/run/luci-sso/handshake_new.json";
		let cache_file = "/var/run/luci-sso/oidc-discovery-123.json";

		with_context({
			fs: {
				data: {
					[old_h_path]: "{}",
					[new_h_path]: "{}",
					[cache_file]: "{}"
				},
				behavior: {
					stat: (path) => {
						if (index(path, "old") > 0) return { mtime: now - 4000 };
						return { mtime: now };
					}
				}
			},
			clock: { data: { now: now } }
		}, (deps) => {
			let res = session.reap_stale_handshakes(deps, 60);
			assert.match(truthy(), res.ok);
			assert.match(1, res.data, "Should report 1 file reaped");

			let files = deps.fs.lsdir("/var/run/luci-sso");
			assert.match(-1, index(files, "handshake_old.json"), "Old handshake should be reaped");
			assert.match(truthy(), index(files, "handshake_new.json") >= 0, "New handshake should remain");
			assert.match(truthy(), index(files, "oidc-discovery-123.json") >= 0, "Discovery caches should NOT be reaped by handshake reaper");
		});
	});
});
