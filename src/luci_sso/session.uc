import * as key from 'luci_sso.session.key';
import * as handshake from 'luci_sso.session.handshake';
import * as token from 'luci_sso.session.token';

/**
 * Facade for the modular session system.
 * Re-exports components for backward compatibility.
 */

// --- Key Management ---
export function get_secret_key(deps) {
	return key.get(deps);
};

// --- Handshake Lifecycle ---
export function create_state(deps) {
	return handshake.create(deps);
};

export function consume_state(deps, handle) {
	return handshake.consume(deps, handle);
};

export function verify_state(deps, handle, clock_tolerance) {
	return handshake.verify(deps, handle, clock_tolerance);
};

export function reap_stale_handshakes(deps, clock_tolerance) {
	return handshake.reap(deps, clock_tolerance);
};

// --- Session Tokens ---
export function create(deps, user_data) {
	return token.create(deps, user_data);
};

export function verify(deps, token_str, clock_tolerance) {
	return token.verify(deps, token_str, clock_tolerance);
};
