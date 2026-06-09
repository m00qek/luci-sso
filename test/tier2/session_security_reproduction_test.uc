import { it, assert, falsy, mock } from 'utest';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';

it('session: security - verify_session truthiness bypass (Audit B1)', () => {
	let now = 1739478000;
	let tolerance = 300;

	mock.inject('fs', {}, (fs) => {
		let deps = { fs, log: () => null, clock: { time: () => now, sleep: () => null } };

		let key = session.get_secret_key(deps).data;

		// 1. exp = 0
		// Before fix: 'if (0 && ...)' skips check, returns ok: true
		// After fix: '0 < now - tol' is true, returns ok: false, error: SESSION_EXPIRED
		let payload_exp0 = { exp: 0, iat: now - 10, sub: "user" };
		let token_exp0 = crypto.jws_sign(payload_exp0, key).data;

		let res_exp0 = session.verify(deps, token_exp0, tolerance);
		assert.match(falsy(), res_exp0.ok, "Session with exp=0 MUST be rejected");
		assert.match("SESSION_EXPIRED", res_exp0.error);

		// 2. missing exp
		// Before fix: 'if (null && ...)' skips check, returns ok: true
		// After fix: 'null == null' is true, returns ok: false, error: MALFORMED_SESSION_TOKEN
		let payload_no_exp = { iat: now - 10, sub: "user" };
		let token_no_exp = crypto.jws_sign(payload_no_exp, key).data;
		let res_no_exp = session.verify(deps, token_no_exp, tolerance);
		assert.match(falsy(), res_no_exp.ok, "Session without exp MUST be rejected");
		assert.match("MALFORMED_SESSION_TOKEN", res_no_exp.error);

		// 3. missing iat
		let payload_no_iat = { exp: now + 3600, sub: "user" };
		let token_no_iat = crypto.jws_sign(payload_no_iat, key).data;
		let res_no_iat = session.verify(deps, token_no_iat, tolerance);
		assert.match(falsy(), res_no_iat.ok, "Session without iat MUST be rejected");
		assert.match("MALFORMED_SESSION_TOKEN", res_no_iat.error);
	});
});
