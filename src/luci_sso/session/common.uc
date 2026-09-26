'use strict';

/**
 * Shared constants and common logic for the session module.
 */

export const HANDSHAKE_DURATION = 300;
export const HANDSHAKE_DIR = "/var/run/luci-sso";
export const REAP_GRACE_PERIOD = 60;
// Most handshakes (logins in progress) that may exist at once. Documented in
// docs/reference/http-api.md; check-request-limits.sh keeps the two in sync.
export const LIMIT_PENDING_HANDSHAKES = 500;

/**
 * Ensures the handshake directory exists.
 * @param {object} deps - { fs }
 */
export function ensure_handshake_dir(deps) {
	try {
		deps.fs.mkdir(HANDSHAKE_DIR, 0700);
	} catch (e) {
		// Might already exist or failed permissions, we'll find out on write
	}
};
