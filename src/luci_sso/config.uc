"use strict";

/**
 * Logic for loading and validating UCI configuration.
 */

import * as Result from 'luci_sso.result';
import * as encoding from 'luci_sso.encoding';
import { SSO_DISABLED, CONFIG_ERROR, UCI_ERROR } from 'luci_sso.errors';

/**
 * Checks if the SSO service is enabled in UCI.
 * @param {object} io - I/O provider
 * @returns {object} - Result Object {ok, data/error}
 */
export function is_enabled(deps) {
	let cursor = deps.uci;
	if (!cursor) return Result.err(UCI_ERROR);

	let enabled = cursor.get("luci-sso", "default", "enabled");
	return Result.ok(enabled === "1");
};

/**
 * Loads the OIDC and Role configuration from UCI. A role carries its name and
 * matching rules only; its permissions are its rpcd login entry.
 * 
 * @param {object} io - I/O provider
 * @returns {object} - Result Object {ok, data/error}
 */
export function load(deps) {
	let enabled_res = is_enabled(deps);
	if (!enabled_res.ok) return enabled_res;
	if (!enabled_res.data) {
		return Result.err(SSO_DISABLED);
	}

	let cursor = deps.uci;

	// 1. Load OIDC Provider Settings
	let oidc_cfg = cursor.get_all("luci-sso", "default");
	if (!oidc_cfg || oidc_cfg[".type"] !== "oidc") {
		return Result.err(CONFIG_ERROR, "OIDC section 'default' missing in /etc/config/luci-sso");
	}

	// 1.1 HTTPS Enforcement
	let issuer = oidc_cfg.issuer_url;
	if (!issuer) {
		return Result.err(CONFIG_ERROR, "issuer_url is mandatory");
	}

	if (!encoding.is_https(issuer)) {
		return Result.err(CONFIG_ERROR, "issuer_url must use HTTPS");
	}

	if (!oidc_cfg.client_id || !oidc_cfg.client_secret) {
		return Result.err(CONFIG_ERROR, "client_id and client_secret are mandatory");
	}

	if (!oidc_cfg.redirect_uri || !encoding.is_https(oidc_cfg.redirect_uri)) {
		return Result.err(CONFIG_ERROR, "redirect_uri is mandatory and must use HTTPS");
	}

	if (oidc_cfg.clock_tolerance == null || oidc_cfg.clock_tolerance == "") {
		return Result.err(CONFIG_ERROR, "clock_tolerance option is mandatory");
	}

	let clock_tolerance = int(oidc_cfg.clock_tolerance);
	if (type(clock_tolerance) != "int") {
		return Result.err(CONFIG_ERROR, "clock_tolerance must be an integer");
	}
	if (clock_tolerance < 0 || clock_tolerance > 3600) {
		return Result.err(CONFIG_ERROR, "clock_tolerance must be between 0 and 3600 seconds");
	}

	// 2. Load and Validate Roles
	let roles = [];
	cursor.foreach("luci-sso", "role", (s) => {
		let emails = (type(s.email) == "array") ? s.email : (s.email ? [ s.email ] : []);
		let groups = (type(s.group) == "array") ? s.group : (s.group ? [ s.group ] : []);

		if (length(emails) == 0 && length(groups) == 0) {
			deps.log("warn", `Ignoring role '${s[".name"]}': missing email or group list`);
			return;
		}

		// A role's permissions live in its rpcd login entry (see ubus.uc), so
		// read/write lists left over from an earlier version grant nothing.
		if (s.read != null || s.write != null)
			deps.log("warn", `Ignoring read/write on role '${s[".name"]}': its permissions are the rpcd login entry 'luci_sso_${s[".name"]}'`);

		push(roles, {
			name: s[".name"],
			emails: emails,
			groups: groups
		});
	});

	if (length(roles) == 0) {
		return Result.err(CONFIG_ERROR, "No valid roles found in /etc/config/luci-sso");
	}

	if (oidc_cfg.internal_issuer_url) {
		if (!encoding.is_https(oidc_cfg.internal_issuer_url))
			return Result.err(CONFIG_ERROR, "internal_issuer_url must use HTTPS");
		// Only the origin is replaced; the issuer's path is kept (see
		// discovery.discover and handshake), so a path here would be ambiguous.
		if (!encoding.is_origin(oidc_cfg.internal_issuer_url))
			return Result.err(CONFIG_ERROR, "internal_issuer_url must be an origin (scheme://host[:port]) with no path, query or fragment");
	}

	return Result.ok({
		issuer_url: oidc_cfg.issuer_url,
		internal_issuer_url: oidc_cfg.internal_issuer_url || oidc_cfg.issuer_url,
		client_id: oidc_cfg.client_id,
		client_secret: oidc_cfg.client_secret,
		redirect_uri: oidc_cfg.redirect_uri,
		scope: oidc_cfg.scope,
		clock_tolerance: clock_tolerance,
		// On unless explicitly turned off, so a config written before the
		// option existed gets the safe behaviour.
		require_email_verified: !(oidc_cfg.require_email_verified in [ "0", "no", "off", "false" ]),
		roles: roles
	});
};

/**
 * Returns true when the claims say the email was verified. The claim is a
 * JSON boolean (OIDC Core 1.0 §5.1), so only the boolean true counts.
 * Anything else, including the string "true" and a missing claim, is false.
 */
export function email_is_verified(claims) {
	return claims.email_verified === true;
};

/**
 * Returns the email that role matching may use, or null. With
 * require_email_verified on (the default, also when the config object does
 * not carry it), an email whose email_verified claim is not true is ignored:
 * an IdP that lets users set their own address unverified could otherwise
 * let anyone claim an admin's email. Groups are not affected.
 */
export function matchable_email(config, claims) {
	let email = claims.email;
	if (type(email) != "string" || email == "") return null;
	if (config.require_email_verified !== false && !email_is_verified(claims)) return null;
	return email;
};

/**
 * Returns the email stored in the session as its `oidc_user` label, or null.
 * Only a verified email (email_is_verified) is stored, whatever
 * require_email_verified says: the label is used to find a user's sessions,
 * and an address the user could set themselves unverified would let those
 * sessions pass for someone else's. That option only governs role matching.
 */
export function session_email(claims) {
	let email = claims.email;
	if (type(email) != "string" || email == "" || !email_is_verified(claims)) return null;
	return email;
};

/**
 * Returns true when the claims match a role, by email (case-insensitive) or
 * by group (exact).
 *
 * Ignoring case in the whole email address is luci-sso's own matching
 * policy, not a standard's rule: RFC 5321 §2.4 lets the local part be
 * case-sensitive, but discourages relying on that, and in practice mail
 * providers treat it as case-insensitive.
 * @private
 */
function _role_matches(role, email, groups) {
	if (email) {
		let lc_email = lc(email);
		for (let e in role.emails) {
			if (lc(e) === lc_email) return true;
		}
	}
	for (let g_claim in groups) {
		for (let g_role in role.groups) {
			if (g_claim === g_role) return true;
		}
	}
	return false;
}

/**
 * Finds the role a user gets: the FIRST role, in config order, whose emails
 * or groups match the claims (matchable_email says when the email counts).
 * A session carries one role's rights, because rpcd rebuilds it from a
 * single login entry; roles are not merged.
 *
 * @param {object} config - The loaded config
 * @param {object} claims - OIDC ID Token claims (email, groups, etc)
 * @returns {object} - Result Object {ok, data: {role_name, also_matched}/error},
 *   where also_matched lists the other matching roles, in order
 */
export function find_role_for_user(config, claims) {
	let email = matchable_email(config, claims);
	let groups = (type(claims.groups) == "array") ? claims.groups : [];
	let matched = [];

	for (let role in config.roles) {
		if (_role_matches(role, email, groups))
			push(matched, role.name);
	}

	if (length(matched) == 0) {
		return Result.err("NO_ROLES_MATCHED");
	}

	return Result.ok({ role_name: matched[0], also_matched: slice(matched, 1) });
};
