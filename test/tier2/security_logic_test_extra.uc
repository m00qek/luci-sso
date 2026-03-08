import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as oidc from 'luci_sso.oidc';
import * as ubus from 'luci_sso.ubus';
import * as crypto from 'luci_sso.crypto';
import * as native from 'luci_sso.native';
import * as mock from 'mock';
import * as f from 'tier2.fixtures';

test('session: handshake - atomic consumption ensures integrity', () => {
	let data = mock.create().with_files({}).spy((io) => {
		let res = session.create_state(io);
		let handle = res.data.token;
		session.verify_state(io, handle, 0);
	});

	assert(data.called("rename", "/var/run/luci-sso/handshake_" + data.all()[0].args[0].token + ".json", "/var/run/luci-sso/handshake_" + data.all()[0].args[0].token + ".json.consumed"));
});

test('security: reject authorization URL generation with short state (B3)', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.get_auth_url(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, { state: "short", nonce: "n1234567890123456", code_challenge: "cc1" });
		assert(!res.ok, "MUST reject short state");
		assert_eq(res.error, "MISSING_STATE_PARAMETER");
	});
});

test('security: reject authorization URL generation without nonce (B1)', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.get_auth_url(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, { state: "s1234567890123456", code_challenge: "cc1" });
		assert(!res.ok, "MUST reject missing nonce");
		assert_eq(res.error, "MISSING_NONCE_PARAMETER");
	});
});

test('security: detect CSPRNG failure during CSRF token generation (B3)', () => {
    crypto.set_native({ ...native, random: () => null });

    let res = null;
    let err = null;
    try {
        mock.create()
            .with_ubus({
                "session:create": { ubus_rpc_session: "sid" }
            }).with_env({}, (io) => {
                res = ubus.create_passwordless_session(io, "root", { read: ["*"], write: ["*"] }, "user@example.com", "at", "rt", "it");
            });
    } catch (e) {
        err = e;
    }
    crypto.set_native(null);
    if (err) die(err);

    assert(!res.ok, "MUST reject session creation if CSPRNG fails");
    assert_eq(res.error, "CRYPTO_SYSTEM_FAILURE");
});
