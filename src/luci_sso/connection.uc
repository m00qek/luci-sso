"use strict";

import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as discovery from 'luci_sso.discovery';
import * as oidc from 'luci_sso.oidc';
import * as Result from 'luci_sso.result';
import { DISCOVERY_NETWORK_ERROR, DISCOVERY_FAILED, INVALID_DISCOVERY_DOC, DISCOVERY_MISSING_ISSUER, DISCOVERY_ISSUER_MISMATCH, DISCOVERY_MISSING_ENDPOINT, INSECURE_ENDPOINT, JWKS_NETWORK_ERROR, JWKS_FETCH_FAILED, INVALID_JWKS_FORMAT, OIDC_INVALID_GRANT, TOKEN_EXCHANGE_FAILED, TOKEN_ENDPOINT_NETWORK_ERROR } from 'luci_sso.errors';

/**
 * The settings page's connection test: checks the provider settings the
 * page holds, saved or not, against the identity provider, through the same
 * code a login runs (discovery.discover, discovery.fetch_jwks,
 * oidc.exchange_code). It changes nothing on the router: the discovery and
 * JWK Set caches are neither read nor written, and nothing is stored.
 *
 * The result is one entry per check, always in this order:
 *
 *   issuer_https        issuer_url is set and uses HTTPS
 *   discovery           the discovery document is fetched (from
 *                       internal_issuer_url's origin when it is set, as at login)
 *   issuer_match        the document's issuer is exactly issuer_url
 *   endpoints           authorization_endpoint, token_endpoint and jwks_uri
 *                       are present and use HTTPS
 *   jwks                the JWK Set loads and has a key luci-sso can verify
 *                       ID tokens with, by the rules a login applies (an
 *                       RSA key of crypto.RSA_MIN_BITS or more, exponent
 *                       65537; an EC key on P-256)
 *   redirect_uri        redirect_uri is set, uses HTTPS and ends in
 *                       CALLBACK_PATH
 *   client_credentials  the token endpoint accepts client_id and client_secret
 *
 * Each entry is { id, status, message }: status is "pass", "fail", "warn"
 * (could not tell) or "skip" (an earlier check failed), and message is a
 * sentence for the administrator. No message carries the client secret, and
 * nothing here logs it.
 */

/** Each HTTP request of the test gives up after this long (see deps.create_probe). */
export const HTTP_TIMEOUT_MS = 5000;

/** The path luci-sso serves the OIDC callback at. */
export const CALLBACK_PATH = "/cgi-bin/luci-sso/callback";

const CHECKS = [ "issuer_https", "discovery", "issuer_match", "endpoints", "jwks", "redirect_uri", "client_credentials" ];

/** How long a value from the provider may be in a message. */
const SHOWN_MAX = 200;

/**
 * A readable reason for a failed request, from its transport cause, such as
 * "HTTP_REQUEST_FAILED (TIMED_OUT)".
 * @private
 */
function _network_reason(cause, url) {
	let c = (type(cause) == "string") ? cause : "";
	if (index(c, "TIMED_OUT") >= 0)
		return `No answer from ${url} within ${HTTP_TIMEOUT_MS / 1000} seconds.`;
	if (index(c, "CERT_UNTRUSTED") >= 0)
		return `The router does not trust the certificate of ${url}. Install the provider's CA certificate on the router.`;
	if (index(c, "CERT_NAME_MISMATCH") >= 0)
		return `The certificate of ${url} does not cover that host name.`;
	if (index(c, "CONNECTION_FAILED") >= 0 || index(c, "CONNECT_NOT_STARTED") >= 0)
		return `Could not connect to ${url}. Check the address, DNS and the firewall.`;
	return `Could not fetch ${url} (${encoding.log_safe(c, SHOWN_MAX) || "unknown error"}).`;
}

/**
 * Whether luci-sso can verify ID tokens with a JWK, judged as a login judges
 * it: a signing key (no "use", or "sig"), whose "alg", if any, is one
 * luci-sso accepts and fits its type, and which converts to a public key
 * (RSA, or EC on P-256), and an RSA key also by the native backends' rules
 * for verifying (crypto.RSA_MIN_BITS and the 65537 exponent). Returns
 * { verdict }: "usable", "short" (an RSA key under crypto.RSA_MIN_BITS, with
 * its size in `bits`), "exponent" (an RSA public exponent other than 65537)
 * or "unusable".
 * @private
 */
function _judge_key(native, jwk) {
	if (type(jwk) != "object") return { verdict: "unusable" };
	if (jwk.use != null && jwk.use !== "sig") return { verdict: "unusable" };
	if (jwk.alg != null) {
		if (index(oidc.ALLOWED_ALGS, jwk.alg) < 0) return { verdict: "unusable" };
		if ((jwk.alg === "RS256" && jwk.kty !== "RSA") || (jwk.alg === "ES256" && jwk.kty !== "EC")) return { verdict: "unusable" };
	}
	if (jwk.kty === "RSA" && type(jwk.n) == "string" && type(jwk.e) == "string") {
		if (!crypto.jwk_rsa_exponent_supported(jwk)) return { verdict: "exponent" };
		let bits = crypto.jwk_rsa_bits(jwk);
		if (bits != null && bits < crypto.RSA_MIN_BITS) return { verdict: "short", bits };
	}
	return { verdict: crypto.jwk_to_pem(native, jwk).ok ? "usable" : "unusable" };
}

/**
 * The sentence for the RSA keys that are too short: "The provider's RSA key
 * is 1024 bits; ...", with each distinct size.
 * @private
 */
function _short_keys(sizes) {
	let uniq = [];
	for (let b in sizes) {
		if (index(uniq, b) < 0) push(uniq, b);
	}
	let what = (length(sizes) == 1) ? "RSA key is" : "RSA keys are";
	return `The provider's ${what} ${join(", ", uniq)} bits; luci-sso requires at least ${crypto.RSA_MIN_BITS}.`;
}

/**
 * A parameter as the page sent it. Nothing is trimmed: a login uses the
 * saved value as it is, so the test must too.
 * @private
 */
function _string(v) {
	return (type(v) == "string") ? v : "";
}

/**
 * Runs the checks, in order, and returns every result.
 *
 * @param {object} deps - { fs, http, native, clock, log }; deps.create_probe
 *   in production, so each request has a short timeout
 * @param {object} params - { issuer_url, internal_issuer_url, client_id,
 *   client_secret, redirect_uri }, as the settings page holds them
 * @returns {object} - Result.ok({ checks: [ { id, status, message } ] })
 */
export function check(deps, params) {
	params = (type(params) == "object") ? params : {};
	let issuer = _string(params.issuer_url);
	let internal = _string(params.internal_issuer_url);
	let client_id = _string(params.client_id);
	let client_secret = _string(params.client_secret);
	let redirect_uri = _string(params.redirect_uri);

	let log = (level, msg) => deps.log(level, `Connection test: ${msg}`);
	let tdeps = { ...deps, log };
	let results = {};
	let set = (id, status, message) => { results[id] = { id, status, message }; };
	let skip_rest = (ids, why) => { for (let id in ids) if (!results[id]) set(id, "skip", why); };

	log("info", "started from the settings page");

	// 1. The issuer URL is HTTPS.
	let doc = null;
	if (!length(issuer)) {
		set("issuer_https", "fail", "Issuer URL is empty. Enter your identity provider's issuer, such as https://auth.example.com.");
	} else if (!encoding.is_https(issuer)) {
		set("issuer_https", "fail", "Issuer URL must start with https://.");
	} else {
		set("issuer_https", "pass", "Issuer URL uses HTTPS.");
	}

	// 2-4. Discovery, fetched as at login, without the cache.
	if (results.issuer_https.status != "pass") {
		skip_rest([ "discovery", "issuer_match", "endpoints", "jwks" ], "Skipped: the Issuer URL must use HTTPS first.");
	} else if (length(internal) && (!encoding.is_https(internal) || !encoding.is_origin(internal))) {
		set("discovery", "fail", "Internal Issuer URL must be an HTTPS origin, such as https://10.0.0.5:8443, with no path.");
		skip_rest([ "issuer_match", "endpoints", "jwks" ], "Skipped: the discovery document could not be fetched.");
	} else {
		let url = discovery.discovery_url(issuer, length(internal) ? internal : null).data;
		let res = discovery.discover(tdeps, issuer, { internal_issuer_url: length(internal) ? internal : null, no_cache: true });
		let d = res.details;
		if (res.ok) {
			doc = res.data;
			set("discovery", "pass", `Fetched the discovery document from ${url}.`);
			set("issuer_match", "pass", "The provider declares exactly this issuer.");
			set("endpoints", "pass", "The authorization, token and JWK Set endpoints are present and use HTTPS.");
		} else if (res.error == DISCOVERY_NETWORK_ERROR) {
			set("discovery", "fail", _network_reason(d, url));
		} else if (res.error == DISCOVERY_FAILED) {
			let status = (type(d) == "object") ? d.upstream_status : null;
			set("discovery", "fail", `${url} answered HTTP ${status}. Check the Issuer URL: the discovery document must be at <issuer>/.well-known/openid-configuration.`);
		} else if (res.error == INVALID_DISCOVERY_DOC) {
			set("discovery", "fail", `${url} did not return a JSON discovery document.`);
		} else if (res.error == DISCOVERY_MISSING_ISSUER) {
			set("discovery", "pass", `Fetched the discovery document from ${url}.`);
			set("issuer_match", "fail", "The discovery document declares no issuer.");
		} else if (res.error == DISCOVERY_ISSUER_MISMATCH) {
			set("discovery", "pass", `Fetched the discovery document from ${url}.`);
			let declared = (type(d) == "object" && type(d.declared) == "string") ? `"${encoding.log_safe(d.declared, SHOWN_MAX)}"` : "no usable issuer";
			let hint = (type(d) == "object" && d.near_miss)
				? " They differ only in a trailing slash, letter case or default port: set Issuer URL to exactly the declared value."
				: " If this is the right provider, set Issuer URL to exactly the declared value.";
			set("issuer_match", "fail", `The provider declares ${declared}, but Issuer URL is "${encoding.log_safe(issuer, SHOWN_MAX)}".${hint}`);
		} else if (res.error == DISCOVERY_MISSING_ENDPOINT) {
			set("discovery", "pass", `Fetched the discovery document from ${url}.`);
			set("issuer_match", "pass", "The provider declares exactly this issuer.");
			set("endpoints", "fail", `The discovery document has no ${d}.`);
		} else if (res.error == INSECURE_ENDPOINT) {
			set("discovery", "pass", `Fetched the discovery document from ${url}.`);
			set("issuer_match", "pass", "The provider declares exactly this issuer.");
			set("endpoints", "fail", `The ${d} in the discovery document does not use HTTPS.`);
		} else {
			set("discovery", "fail", `The discovery document could not be used (${res.error}).`);
		}
		if (!doc)
			skip_rest([ "issuer_match", "endpoints", "jwks" ], "Skipped: needs a usable discovery document.");
	}

	// Split-horizon: the back channel goes to the internal origin, as at login.
	let backchannel = doc ? discovery.backchannel(doc, issuer, length(internal) ? internal : null) : null;

	// 5. The JWK Set, without the cache.
	if (backchannel && !results.jwks) {
		let uri = backchannel.jwks_uri;
		let res = discovery.fetch_jwks(tdeps, uri, { no_cache: true });
		let d = res.details;
		if (res.ok) {
			let judged = map(res.data, (k) => _judge_key(deps.native, k));
			let usable = length(filter(judged, (j) => j.verdict == "usable"));
			let short = map(filter(judged, (j) => j.verdict == "short"), (j) => j.bits);
			let total = length(res.data);
			if (usable > 0)
				set("jwks", "pass", `The JWK Set has ${total} key(s); ${usable} can verify ID tokens (RS256, or ES256 on P-256)` +
					(length(short) ? `; ${length(short)} cannot, being RSA keys under ${crypto.RSA_MIN_BITS} bits.` : "."));
			else if (length(short))
				set("jwks", "fail", _short_keys(short));
			else if (length(filter(judged, (j) => j.verdict == "exponent")))
				set("jwks", "fail", `The provider's RSA key has a public exponent other than 65537 (AQAB), the only one luci-sso accepts.`);
			else
				set("jwks", "fail", `The JWK Set has ${total} key(s), but none luci-sso can verify ID tokens with: it needs an RS256 (RSA) or ES256 (EC P-256) signing key.`);
		} else if (res.error == JWKS_NETWORK_ERROR) {
			set("jwks", "fail", _network_reason(d, uri));
		} else if (res.error == JWKS_FETCH_FAILED) {
			set("jwks", "fail", `${uri} answered HTTP ${(type(d) == "object") ? d.upstream_status : null}.`);
		} else if (res.error == INVALID_JWKS_FORMAT) {
			set("jwks", "fail", `${uri} did not return a JWK Set (a JSON object with a "keys" array).`);
		} else {
			set("jwks", "fail", `The JWK Set could not be fetched (${res.error}).`);
		}
	}

	// 6. The redirect URI.
	if (!length(redirect_uri)) {
		set("redirect_uri", "fail", `Redirect URI is empty. Set it to https://<the address you open LuCI at>${CALLBACK_PATH}.`);
	} else if (!encoding.is_https(redirect_uri)) {
		set("redirect_uri", "fail", "Redirect URI must start with https://.");
	} else if (length(redirect_uri) < length(CALLBACK_PATH) || substr(redirect_uri, -length(CALLBACK_PATH)) != CALLBACK_PATH) {
		set("redirect_uri", "fail", `Redirect URI must end in ${CALLBACK_PATH}.`);
	} else {
		set("redirect_uri", "pass", "Redirect URI uses HTTPS and ends in the callback path. The provider must list this exact address.");
	}

	// 7. The client credentials: a token request with a made-up code, sent
	// exactly as at login (client_secret_post, a fresh PKCE verifier). The
	// provider checks the client before the code (RFC 6749 §3.2.1), so
	// invalid_grant means the credentials passed; nothing is stored.
	if (!backchannel) {
		set("client_credentials", "skip", "Skipped: needs the token endpoint from the discovery document.");
	} else if (!length(client_id) || !length(client_secret)) {
		set("client_credentials", "fail", "Client ID and Client Secret are both required.");
	} else {
		let rnd = crypto.random(deps.native, 16);
		let pkce = crypto.pkce_pair(deps.native, 32);
		if (!rnd.ok || !pkce.ok) {
			set("client_credentials", "warn", "Couldn't run the check: the router could not generate random values.");
		} else {
			let code = "luci-sso-connection-test-" + encoding.b64url_encode(rnd.data).data;
			let cfg = { client_id, client_secret, redirect_uri: length(redirect_uri) ? redirect_uri : null };
			// The probe expects the token request to fail, and the page
			// reports the outcome: log what exchange_code says at info, so the
			// expected refusal does not read as an error in the system log.
			let probe_deps = { ...tdeps, log: (level, msg) => log("info", msg) };
			let res = oidc.exchange_code(probe_deps, cfg, backchannel, code, pkce.data.verifier, null);
			let d = (type(res.details) == "object") ? res.details : {};
			let answer = d.oauth_error ? d.oauth_error : `HTTP ${d.upstream_status}`;
			if (res.ok) {
				set("client_credentials", "warn", "Couldn't determine: the token endpoint accepted a made-up authorization code, which it never should. Check the provider.");
			} else if (res.error == OIDC_INVALID_GRANT) {
				set("client_credentials", "pass", "The provider accepted the Client ID and Client Secret (it refused only the test's made-up authorization code, as expected).");
			} else if (res.error == TOKEN_EXCHANGE_FAILED && (d.oauth_error == "invalid_client" || d.upstream_status == 401)) {
				set("client_credentials", "fail", `The provider rejected the Client ID or Client Secret (${answer}). Copy both again from the provider.`);
			} else if (res.error == TOKEN_EXCHANGE_FAILED) {
				set("client_credentials", "warn", `Couldn't determine whether the Client ID and Client Secret are right: the provider answered ${answer}.`);
			} else if (res.error == TOKEN_ENDPOINT_NETWORK_ERROR) {
				set("client_credentials", "fail", _network_reason(d.cause, backchannel.token_endpoint));
			} else {
				set("client_credentials", "warn", `Couldn't determine whether the Client ID and Client Secret are right (${res.error}).`);
			}
		}
	}

	let checks = map(CHECKS, (id) => results[id]);
	let count = (st) => length(filter(checks, (c) => c.status == st));
	log("info", `finished: ${count("pass")} passed, ${count("fail")} failed, ${count("warn")} undetermined, ${count("skip")} skipped`);

	return Result.ok({ checks });
};
