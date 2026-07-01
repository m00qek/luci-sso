import * as crypto from 'luci_sso.crypto';
import * as Result from 'luci_sso.result';
import * as common from 'luci_sso.session.common';
import * as key from 'luci_sso.session.key';

/**
 * Session token management (creation and verification).
 */

/**
 * Creates a signed session token.
 *
 * @param {*} deps Service dependencies: `deps.fs`, `deps.clock`, `deps.native`, `deps.log`.
 * @param {*} user_data User claims from the OIDC ID token; must include `sub` or `email` as strings.
 * @returns {Result}
 */
export function create(deps, user_data) {
	if (!user_data || (type(user_data.sub) !== "string" && type(user_data.email) !== "string")) {
		return Result.err("INVALID_USER_DATA");
	}

	let res = key.get(deps);
	if (!res.ok) return res;
	let secret = res.data;

	let now = deps.clock.time();
	let payload = {
		user: user_data.email || user_data.sub,
		name: user_data.name,
		iat: now,
		exp: now + common.SESSION_DURATION
	};

	return crypto.jws_sign(deps.native, payload, secret);
};

/**
 * Verifies a session token and returns the session object.
 *
 * @param {*} deps Service dependencies: `deps.fs`, `deps.clock`, `deps.native`, `deps.log`.
 * @param {string} token_str Signed JWS session token as issued by `token.create`.
 * @param {int} clock_tolerance Clock skew tolerance in seconds for `iat`/`exp` validation.
 * @returns {Result}
 */
export function verify(deps, token_str, clock_tolerance) {
	if (!token_str) return Result.err("NO_SESSION");
	if (type(token_str) !== "string") die("CONTRACT_VIOLATION: verify expects string token");
	if (type(clock_tolerance) !== "int") die("CONTRACT_VIOLATION: verify expects mandatory integer clock_tolerance");

	let res = key.get(deps);
	if (!res.ok) return res;
	let secret = res.data;

	let result = crypto.jws_verify(deps.native, token_str, secret);
	if (!result.ok) return Result.err("SESSION_SIGNATURE_INVALID", result.error);

	let session = result.data;
	let now = deps.clock.time();

	if (session.exp === null || type(session.exp) !== "int") {
		return Result.err("MALFORMED_SESSION_TOKEN");
	}
	if (session.exp < (now - clock_tolerance)) {
		return Result.err("SESSION_EXPIRED");
	}

	if (session.iat === null || type(session.iat) !== "int") {
		return Result.err("MALFORMED_SESSION_TOKEN");
	}
	if (session.iat > (now + clock_tolerance)) {
		return Result.err("SESSION_NOT_YET_VALID");
	}

	return Result.ok(session);
};
