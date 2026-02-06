/**
 * Tier 3 Integration Fixtures
 * 
 * This file contains the "Anchor Token" and corresponding JWK used for
 * behavioral testing of the router and handshake logic.
 * 
 * Uses HS256 (Symmetric) for simplicity and to avoid mocking crypto.
 * 
 * DO NOT use these in Unit Tests.
 */

// HS256 Secret (Anchor)
export const ANCHOR_SECRET = "anchor-secret-32-character-str!!!";

// Symmetric JWK (Anchor)
export const ANCHOR_JWK = {
	kty: "oct",
	kid: "anchor-key-2026",
	use: "sig",
	alg: "HS256",
	k: "YW5jaG9yLXNlY3JldC0zMi1jaGFyYWN0ZXItc3RyISEh" // base64url of ANCHOR_SECRET
};

/**
 * Generates a valid Anchor Token for a specific issuer and email.
 * @param {object} crypto - The crypto module
 * @param {string} issuer - Expected issuer
 * @param {string} email - User email
 * @param {number} now - Current time
 */
export function sign_anchor_token(crypto, issuer, email, now) {
	let payload = {
		sub: email,
		email: email,
		iss: issuer,
		aud: "luci-app",
		iat: now,
		exp: now + 300,
		nonce: "test-nonce"
	};
	// We use sign_jws which creates HS256
	return crypto.sign_jws(payload, ANCHOR_SECRET);
};