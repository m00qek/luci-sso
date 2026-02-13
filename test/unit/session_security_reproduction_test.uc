import { test, assert, assert_eq } from 'testing';
import * as session from 'luci_sso.session';
import * as crypto from 'luci_sso.crypto';
import * as mock from 'mock';

test('session: security - verify_session truthiness bypass (Audit B1)', () => {
	let factory = mock.create();
	let now = 1739478000; // Fixed timestamp
	let tolerance = 300;
	
	factory.with_env({ time: now }, (io) => {
		// Get a valid secret key
		let key = session.get_secret_key(io).data;
		
		// 1. exp = 0
		// Before fix: 'if (0 && ...)' skips check, returns ok: true
		// After fix: '0 < now - tol' is true, returns ok: false, error: SESSION_EXPIRED
		let payload_exp0 = { exp: 0, iat: now - 10, sub: "user" };
		let token_exp0 = crypto.sign_jws(payload_exp0, key);
		
		let res_exp0 = session.verify(io, token_exp0, tolerance);
		assert(!res_exp0.ok, "Session with exp=0 MUST be rejected");
		assert_eq(res_exp0.error, "SESSION_EXPIRED");
		
		// 2. missing exp
		// Before fix: 'if (null && ...)' skips check, returns ok: true
		// After fix: 'null == null' is true, returns ok: false, error: INVALID_SESSION
		let payload_no_exp = { iat: now - 10, sub: "user" };
		let token_no_exp = crypto.sign_jws(payload_no_exp, key);
		let res_no_exp = session.verify(io, token_no_exp, tolerance);
		assert(!res_no_exp.ok, "Session without exp MUST be rejected");
		assert_eq(res_no_exp.error, "INVALID_SESSION");

		// 3. missing iat
		let payload_no_iat = { exp: now + 3600, sub: "user" };
		let token_no_iat = crypto.sign_jws(payload_no_iat, key);
		let res_no_iat = session.verify(io, token_no_iat, tolerance);
		assert(!res_no_iat.ok, "Session without iat MUST be rejected");
		assert_eq(res_no_iat.error, "INVALID_SESSION");
	});
});
