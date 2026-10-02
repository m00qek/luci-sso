"use strict";

import * as crypto from 'luci_sso.crypto';
import * as encoding from 'luci_sso.encoding';
import * as discovery from 'luci_sso.discovery';
import * as oidc from 'luci_sso.oidc';
import * as Result from 'luci_sso.result';
import { DISCOVERY_NETWORK_ERROR, DISCOVERY_FAILED, INVALID_DISCOVERY_DOC, DISCOVERY_MISSING_ISSUER, DISCOVERY_ISSUER_MISMATCH, DISCOVERY_MISSING_ENDPOINT, INSECURE_ENDPOINT, JWKS_NETWORK_ERROR, JWKS_FETCH_FAILED, INVALID_JWKS_FORMAT, OIDC_INVALID_GRANT, TOKEN_EXCHANGE_FAILED, TOKEN_ENDPOINT_NETWORK_ERROR, UNSUPPORTED_KTY, UNSUPPORTED_CURVE } from 'luci_sso.errors';

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
 *   jwks                the JWK Set loads, and the keys a login can pick
 *                       (discovery.find_jwk: the first key with the ID
 *                       token's kid, or the first key for a token without
 *                       one) can verify ID tokens, by the rules a login
 *                       applies (an RSA key of crypto.RSA_MIN_BITS or more,
 *                       exponent 65537; an EC key on P-256); see _jwks_check
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

/**
 * The longest reply run() writes, in bytes. The rpcd plugin reads the reply
 * once the helper process has exited, so it must fit a pipe's buffer (64 KiB
 * on Linux): a longer write would block the helper until it is killed.
 */
export const MAX_REPLY = 32768;

/** The path luci-sso serves the OIDC callback at. */
export const CALLBACK_PATH = "/cgi-bin/luci-sso/callback";

const CHECKS = [ "issuer_https", "discovery", "issuer_match", "endpoints", "jwks", "redirect_uri", "client_credentials" ];

/** How long a value from the provider may be in a message. */
const SHOWN_MAX = 200;

/**
 * A value from the provider, or the form, as a message quotes it: made safe
 * for the log (encoding.log_safe), and with "<" and ">" as "?", which no
 * URL or OAuth error code may hold unencoded. The settings page shows the
 * messages as text; this is a second line of defence, should a page ever
 * put one into HTML.
 * @private
 */
function _shown(v) {
	return replace(encoding.log_safe(v, SHOWN_MAX), /[<>]/g, "?");
}

/**
 * A readable reason for a failed request, from its transport cause, such as
 * "HTTP_REQUEST_FAILED (TIMED_OUT)".
 * @private
 */
function _network_reason(cause, url) {
	let c = (type(cause) == "string") ? cause : "";
	url = _shown(url);
	if (index(c, "TIMED_OUT") >= 0)
		return `No answer from ${url} within ${HTTP_TIMEOUT_MS / 1000} seconds.`;
	if (index(c, "CERT_UNTRUSTED") >= 0)
		return `The router does not trust the certificate of ${url}. Install the provider's CA certificate on the router.`;
	if (index(c, "CERT_NAME_MISMATCH") >= 0)
		return `The certificate of ${url} does not cover that host name.`;
	if (index(c, "CONNECTION_FAILED") >= 0 || index(c, "CONNECT_NOT_STARTED") >= 0)
		return `Could not connect to ${url}. Check the address, DNS and the firewall.`;
	return `Could not fetch ${url} (${_shown(c) || "unknown error"}).`;
}

/**
 * Whether a login can verify ID tokens with a JWK, judged as a login judges
 * it once discovery.find_jwk has picked it: it must convert to a public key
 * (crypto.jwk_to_pem: RSA, or EC on P-256), an RSA key must also pass the
 * native backends' rules for verifying (crypto.RSA_MIN_BITS and the 65537
 * exponent), and an "alg" it declares must be one luci-sso accepts for its
 * type, since the provider signs with that algorithm. Its "use" is not
 * looked at: a login does not look at it either. Never throws, whatever the
 * provider sent.
 *
 * Returns { verdict, why }: verdict is "usable", "short" (an RSA key under
 * crypto.RSA_MIN_BITS, with its size in `bits`), "exponent" (an RSA public
 * exponent other than 65537), "malformed" (it cannot be read as a key),
 * "unsupported" (another type or curve) or "alg"; `why` says it in words.
 * @private
 */
function _judge_key(native, jwk) {
	if (jwk === null || type(jwk) != "object")
		return { verdict: "malformed", why: "not a JSON object" };
	if (jwk.kty === "RSA" && type(jwk.n) == "string" && type(jwk.e) == "string") {
		if (!crypto.jwk_rsa_exponent_supported(jwk))
			return { verdict: "exponent", why: "an RSA key whose public exponent is not 65537 (AQAB)" };
		let bits = crypto.jwk_rsa_bits(jwk);
		if (bits != null && bits < crypto.RSA_MIN_BITS)
			return { verdict: "short", bits, why: `an RSA key of ${bits} bits, under ${crypto.RSA_MIN_BITS}` };
	}
	let pem = crypto.jwk_to_pem(native, jwk);
	if (!pem.ok) {
		if (pem.error == UNSUPPORTED_KTY || pem.error == UNSUPPORTED_CURVE)
			return { verdict: "unsupported", why: "neither an RSA key nor an EC key on P-256" };
		return { verdict: "malformed", why: "malformed: it cannot be read as an RSA or EC public key" };
	}
	if (jwk.alg != null) {
		let alg = (type(jwk.alg) == "string") ? jwk.alg : "";
		let fits = (alg === "RS256" && jwk.kty === "RSA") || (alg === "ES256" && jwk.kty === "EC");
		if (index(oidc.ALLOWED_ALGS, alg) < 0 || !fits)
			return { verdict: "alg", why: `a key for "${_shown(sprintf("%s", jwk.alg))}", an algorithm luci-sso does not accept for it` };
	}
	return { verdict: "usable", why: "can verify ID tokens" };
}

/**
 * The sentence for the RSA keys that are too short: "The provider's RSA key
 * is 1024 bits; ...", with each distinct size.
 * @private
 */
function _short_keys(sizes) {
	let uniq_sizes = [];
	for (let b in sizes) {
		if (index(uniq_sizes, b) < 0) push(uniq_sizes, b);
	}
	let what = (length(sizes) == 1) ? "RSA key is" : "RSA keys are";
	return `The provider's ${what} ${join(", ", uniq_sizes)} bits; luci-sso requires at least ${crypto.RSA_MIN_BITS}.`;
}

/** How many keys a jwks message describes one by one. */
const KEYS_SHOWN_MAX = 10;

/**
 * The jwks check's result for the keys of a JWK Set.
 *
 * A login picks one key per ID token, with discovery.find_jwk, which this
 * calls rather than copies: the first key whose kid is the token's, or the
 * first key of the set for a token without a kid. Every key is judged with
 * _judge_key, and described in the message, with whether a login ever picks
 * it. The status:
 *
 *   fail  no key a login can pick can verify ID tokens
 *   warn  some can, but the first key cannot (so a token without a kid
 *         fails), or a signing key a login picks by its kid cannot
 *   pass  every key a login can pick can verify ID tokens
 *
 * A key marked for encryption (a "use" other than "sig") that a login picks
 * only by its kid is described but never fails or warns: the provider does
 * not sign ID tokens with it. As the first key, it counts like any other,
 * since a token without a kid is checked with it.
 * @private
 */
function _jwks_check(native, keys) {
	let total = length(keys);
	if (!total)
		return { status: "fail", message: "The JWK Set has no keys." };

	let first = discovery.find_jwk(keys, null).data;
	let judged = [];
	for (let i, k in keys) {
		let is_object = (k !== null && type(k) == "object");
		let has_kid = is_object && !!k.kid;
		let by_kid = has_kid && discovery.find_jwk(keys, k.kid).data === k;
		let label = (has_kid && type(k.kid) == "string") ? `'${_shown(k.kid)}'` : `#${i + 1}`;
		let signing = !is_object || k.use == null || k.use === "sig";
		let use = (signing || type(k.use) != "string") ? null : k.use;
		push(judged, { ...(_judge_key(native, k)), label, first: (i == 0 && k === first), by_kid, signing, use });
	}

	let picked = filter(judged, (j) => j.first || j.by_kid);
	let usable = filter(picked, (j) => j.verdict == "usable");
	let failing = filter(picked, (j) => j.verdict != "usable" && (j.first || j.signing));

	let describe = (j) => {
		let note = j.why;
		if (!j.signing) note += (j.use != null) ? `; not for signing (use "${_shown(j.use)}")` : "; not for signing";
		if (!j.first && !j.by_kid) note += "; a login never picks it";
		return `${j.label}: ${note}`;
	};
	let shown = map(slice(judged, 0, KEYS_SHOWN_MAX), describe);
	let rest = total - length(shown);
	let listing = ` Keys: ${join("; ", shown)}${rest > 0 ? `; and ${rest} more` : ""}.`;

	if (!length(usable)) {
		let reasons = [];
		for (let j in failing)
			if (index(reasons, j.verdict) < 0) push(reasons, j.verdict);
		let summary;
		if (length(reasons) == 1 && reasons[0] == "short")
			summary = _short_keys(map(failing, (j) => j.bits));
		else if (length(reasons) == 1 && reasons[0] == "exponent")
			summary = "The provider's RSA key has a public exponent other than 65537 (AQAB), the only one luci-sso accepts.";
		else
			summary = `No key a login would pick can verify ID tokens: luci-sso needs an RSA key of at least ${crypto.RSA_MIN_BITS} bits with the exponent 65537, or an EC key on P-256.`;
		return { status: "fail", message: summary + listing };
	}

	if (length(failing)) {
		let parts = [];
		let first_failing = filter(failing, (j) => j.first);
		if (length(first_failing))
			push(parts, `An ID token without a kid would fail: a login checks it with the first key, ${first_failing[0].label}, which is ${first_failing[0].why}.`);
		let by_kid = filter(failing, (j) => !j.first);
		if (length(by_kid))
			push(parts, `An ID token naming ${join(", ", map(by_kid, (j) => j.label))} would fail.`);
		push(parts, `Tokens a login checks with ${join(", ", map(usable, (j) => j.label))} verify.`);
		return { status: "warn", message: join(" ", parts) + listing };
	}

	return { status: "pass", message: `The JWK Set has ${total} key(s); every key a login would pick can verify ID tokens (RS256, or ES256 on P-256).` + listing };
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
		let url = _shown(discovery.discovery_url(issuer, length(internal) ? internal : null).data);
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
			let declared = (type(d) == "object" && type(d.declared) == "string") ? `"${_shown(d.declared)}"` : "no usable issuer";
			let hint = (type(d) == "object" && d.near_miss)
				? " They differ only in a trailing slash, letter case or default port: set Issuer URL to exactly the declared value."
				: " If this is the right provider, set Issuer URL to exactly the declared value.";
			set("issuer_match", "fail", `The provider declares ${declared}, but Issuer URL is "${_shown(issuer)}".${hint}`);
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
			let verdict = _jwks_check(deps.native, res.data);
			set("jwks", verdict.status, verdict.message);
		} else if (res.error == JWKS_NETWORK_ERROR) {
			set("jwks", "fail", _network_reason(d, uri));
		} else if (res.error == JWKS_FETCH_FAILED) {
			set("jwks", "fail", `${_shown(uri)} answered HTTP ${(type(d) == "object") ? d.upstream_status : null}.`);
		} else if (res.error == INVALID_JWKS_FORMAT) {
			set("jwks", "fail", `${_shown(uri)} did not return a JWK Set (a JSON object with a "keys" array).`);
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
			let answer = d.oauth_error ? _shown(d.oauth_error) : `HTTP ${d.upstream_status}`;
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

/**
 * The connection test as its helper process runs it: parses the parameters,
 * which the rpcd plugin writes to the helper's standard input, runs check(),
 * and returns the reply for the settings page as JSON text, at most
 * MAX_REPLY bytes.
 *
 * The helper is /usr/libexec/luci-sso/connection-test, which the plugin
 * starts with fork and exec: none of rpcd's state (its ubus connection, its
 * event loop, its signal handlers) reaches the checks. The parameters
 * include the client secret, so they travel only through the pipe, never on
 * the command line or in the environment, and the reply never carries it.
 *
 * @param {object} deps - deps.create_probe(HTTP_TIMEOUT_MS)
 * @param {*} input - The parameters as JSON text: { issuer_url,
 *   internal_issuer_url, client_id, client_secret, redirect_uri }
 * @returns {string} - The JSON of { done: true, checks: [ { id, status,
 *   message } ] }, or of { done: true, error: "TEST_FAILED", message }
 */
export function run(deps, input) {
	let failed = (message) => sprintf("%J", { done: true, error: "TEST_FAILED", message });
	let parsed = encoding.safe_json(input);
	if (!parsed.ok || type(parsed.data) != "object")
		return failed("the test received no settings");
	let res = check(deps, parsed.data);
	if (!res.ok)
		return failed(`${res.error}`);
	let out = sprintf("%J", { done: true, checks: res.data.checks });
	return (length(out) <= MAX_REPLY) ? out : failed("the test's result is too long");
};
