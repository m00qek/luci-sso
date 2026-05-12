import * as key from 'luci_sso.session.key';
import * as handshake from 'luci_sso.session.handshake';
import * as token from 'luci_sso.session.token';

/**
 * Facade for the modular session system.
 * Re-exports components for backward compatibility.
 */

// --- Key Management ---
export function get_secret_key(io) {
	return key.get(io);
};

// --- Handshake Lifecycle ---
export function create_state(io) {
	return handshake.create(io);
};

export function consume_state(io, handle) {
	return handshake.consume(io, handle);
};

export function verify_state(io, handle, clock_tolerance) {
	return handshake.verify(io, handle, clock_tolerance);
};

export function reap_stale_handshakes(io, clock_tolerance) {
	return handshake.reap(io, clock_tolerance);
};

// --- Session Tokens ---
export function create(io, user_data) {
	return token.create(io, user_data);
};

export function verify(io, token_str, clock_tolerance) {
	return token.verify(io, token_str, clock_tolerance);
};
