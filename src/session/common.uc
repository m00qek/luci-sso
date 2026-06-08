'use strict';

/**
 * Shared constants and common logic for the session module.
 */

export const SECRET_KEY_PATH = "/etc/luci-sso/secret.key";
export const SESSION_DURATION = 3600;
export const HANDSHAKE_DURATION = 300;
export const HANDSHAKE_DIR = "/var/run/luci-sso";
export const REAP_GRACE_PERIOD = 60;
export const HANDSHAKE_MAX_COUNT = 100;

/**
 * Ensures the handshake directory exists.
 * @param {object} io - I/O provider
 */
export function ensure_handshake_dir(io) {
	try {
		io.mkdir(HANDSHAKE_DIR, 0700);
	} catch (e) {
		// Might already exist or failed permissions, we'll find out on write
	}
};
