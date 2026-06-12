import { describe, it, assert, truthy, falsy, spy } from 'utest';
import * as session from 'luci_sso.session';
import * as oidc from 'luci_sso.oidc';
import * as ubus from 'luci_sso.ubus';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import { with_context } from 'context';
import * as f from 'tier2.fixtures';

describe('session: handshake', () => {
	it('atomic consumption ensures integrity', () => {
		with_context({
			fs: { data: {} },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = session.create_state(deps);
			let handle = res.data.token;
			session.verify_state(deps, handle, 0);

			let rename_calls = spy(deps.fs).calls.rename;
			assert.match(truthy(), length(rename_calls) > 0, "Should have used rename for atomicity");
		});
	});

	it('state is single-use only', () => {
		with_context({
			fs: { data: {} },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = session.create_state(deps);
			let handle = res.data.token;

			let res_1 = session.verify_state(deps, handle, 0);
			assert.match(truthy(), res_1.ok, "First consumption should succeed");

			let res_2 = session.verify_state(deps, handle, 0);
			assert.match(falsy(), res_2.ok, "Second consumption should fail");

			let res_3 = session.verify_state(deps, handle, 0);
			assert.match(falsy(), res_3.ok, "Third consumption should fail");
			assert.match("STATE_NOT_FOUND", res_3.error);
		});
	});

	it('traversal attempts are rejected', () => {
		with_context({ fs: { data: {} } }, (deps) => {
			let res = session.verify_state(deps, "../../../etc/passwd", 0);
			assert.match(falsy(), res.ok, "Should reject traversal attempt");
			assert.match("MALFORMED_STATE_COOKIE", res.error);
		});
	});

	it('malformed JSON fails closed', () => {
		const handle = "malformed_handle";
		const path = `/var/run/luci-sso/handshake_${handle}.json`;

		with_context({
			fs: { data: { [path]: "{ invalid: json" } },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = session.verify_state(deps, handle, 0);
			assert.match(falsy(), res.ok, "Should fail on malformed JSON");
			assert.match("STATE_CORRUPTED", res.error);
		});
	});

	it('filesystem error fails closed', () => {
		let handle = null;
		let handshake_content = null;

		with_context({
			fs: { data: {} },
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res = session.create_state(deps);
			handle = res.data.token;
			handshake_content = deps.fs.readfile(`/var/run/luci-sso/handshake_${handle}.json`);
		});

		with_context({
			fs: {
				data: { [`/var/run/luci-sso/handshake_${handle}.json`]: handshake_content },
				behavior: { rename: (old_path, new_path) => false }
			},
			clock: { data: { now: 1516239022 } }
		}, (deps) => {
			let res_fs = session.verify_state(deps, handle, 0);
			assert.match(falsy(), res_fs.ok, "Should fail when rename is impossible");
			assert.match("STATE_NOT_FOUND", res_fs.error);
		});
	});
});

describe('security', () => {
	it('reject authorization URL generation without state (B1)', () => {
		with_context({}, (deps) => {
			let res = oidc.get_auth_url(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, { nonce: "n1234567890123456", code_challenge: "cc1" });
			assert.match(truthy(), type(res) == "object" && !res.ok, "MUST return error object if state is missing");
			assert.match("MISSING_STATE_PARAMETER", res.error);
		});
	});

	it('reject authorization URL generation with short state (B3)', () => {
		with_context({}, (deps) => {
			let res = oidc.get_auth_url(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, { state: "short", nonce: "n1234567890123456", code_challenge: "cc1" });
			assert.match(falsy(), res.ok, "MUST reject short state");
			assert.match("MISSING_STATE_PARAMETER", res.error);
		});
	});

	it('reject authorization URL generation without nonce (B1)', () => {
		with_context({}, (deps) => {
			let res = oidc.get_auth_url(deps, f.MOCK_CONFIG, f.MOCK_DISCOVERY, { state: "s1234567890123456", code_challenge: "cc1" });
			assert.match(falsy(), res.ok, "MUST reject missing nonce");
			assert.match("MISSING_NONCE_PARAMETER", res.error);
		});
	});

	it('detect CSPRNG failure during CSRF token generation (B3)', () => {
		crypto.set_native({ ...native, random: () => null });

		let res = null;
		let err = null;
		try {
			with_context({
				fs: {},
				ubus: {
					data: {
						"session:create": { ubus_rpc_session: "sid" },
						"session:grant": {},
						"session:set": {}
					}
				}
			}, (deps) => {
				res = ubus.create_passwordless_session(deps, "root", { read: ["*"], write: ["*"] }, "user@example.com", "at", "rt", "it");
			});
		} catch (e) {
			err = e;
		}
		crypto.set_native(null);
		if (err) die(err);

		assert.match(falsy(), res.ok, "MUST reject session creation if CSPRNG fails");
		assert.match("CRYPTO_INIT_FAILED", res.error);
	});
});
