/**
 * Logic for loading and validating UCI configuration.
 */

import * as Result from 'luci_sso.result';

/**
 * Checks if the SSO service is enabled in UCI.
 * @param {object} io - I/O provider
 * @returns {boolean}
 */
export function is_enabled(io) {
	let cursor = io.uci_cursor();
	let enabled = cursor.get("luci-sso", "default", "enabled");
	return (enabled === '1');
};

/**
 * Loads the OIDC and Role configuration from UCI.
 * 
 * @param {object} io - I/O provider
 * @returns {object} - Result Object {ok, data/error}
 */
export function load(io) {
	if (!is_enabled(io)) {
		return Result.err("DISABLED");
	}

	let cursor = io.uci_cursor();

	// 1. Load OIDC Provider Settings
	let oidc_cfg = cursor.get_all("luci-sso", "default");
	if (!oidc_cfg || oidc_cfg[".type"] !== "oidc") {
		return Result.err("CONFIG_ERROR", "OIDC section 'default' missing in /etc/config/luci-sso");
	}

	// 1.1 HTTPS Enforcement
	let issuer = oidc_cfg.issuer_url;
	if (!issuer) {
		return Result.err("CONFIG_ERROR", "issuer_url is mandatory");
	}

	if (substr(issuer, 0, 8) !== "https://") {
		return Result.err("CONFIG_ERROR", "issuer_url must use HTTPS");
	}

	if (!oidc_cfg.client_id || !oidc_cfg.client_secret) {
		return Result.err("CONFIG_ERROR", "client_id and client_secret are mandatory");
	}

	if (!oidc_cfg.redirect_uri || substr(oidc_cfg.redirect_uri, 0, 8) !== "https://") {
		return Result.err("CONFIG_ERROR", "redirect_uri is mandatory and must use HTTPS");
	}

	if (oidc_cfg.clock_tolerance == null || oidc_cfg.clock_tolerance == "") {
		return Result.err("CONFIG_ERROR", "clock_tolerance option is mandatory");
	}

	let clock_tolerance = int(oidc_cfg.clock_tolerance);
	if (type(clock_tolerance) != "int") {
		return Result.err("CONFIG_ERROR", "clock_tolerance must be an integer");
	}

	// 2. Load and Validate Roles
	let roles = [];
	cursor.foreach("luci-sso", "role", (s) => {
		let emails = (type(s.email) == "array") ? s.email : (s.email ? [ s.email ] : []);
		let groups = (type(s.group) == "array") ? s.group : (s.group ? [ s.group ] : []);
		let read = (type(s.read) == "array") ? s.read : (s.read ? [ s.read ] : []);
		let write = (type(s.write) == "array") ? s.write : (s.write ? [ s.write ] : []);

		if (length(emails) == 0 && length(groups) == 0) {
			io.log("warn", `Ignoring role '${s[".name"]}': missing email or group list`);
			return;
		}

		push(roles, {
			name: s[".name"],
			emails: emails,
			groups: groups,
			read: read,
			write: write
		});
	});

	if (length(roles) == 0) {
		return Result.err("CONFIG_ERROR", "No valid roles found in /etc/config/luci-sso");
	}

	return Result.ok({
		issuer_url: oidc_cfg.issuer_url,
		internal_issuer_url: oidc_cfg.internal_issuer_url || oidc_cfg.issuer_url,
		client_id: oidc_cfg.client_id,
		client_secret: oidc_cfg.client_secret,
		redirect_uri: oidc_cfg.redirect_uri,
		scope: oidc_cfg.scope,
		clock_tolerance: clock_tolerance,
		roles: roles
	});
};

/**
 * Maps OIDC user claims to matched permissions (read/write lists).
 * 
 * @param {object} config - The loaded config
 * @param {object} claims - OIDC ID Token claims (email, groups, etc)
 * @returns {object} - { read: [], write: [], role_name: "..." }
 */
export function find_roles_for_user(config, claims) {
	let perms = { read: [], write: [], role_name: null };
	let email = claims.email;
	let groups = (type(claims.groups) == "array") ? claims.groups : [];

	for (let role in config.roles) {
		let matched = false;

		// Match email
		if (email) {
			for (let e in role.emails) {
				if (e == email) {
					matched = true;
					break;
				}
			}
		}

		// Match groups
		if (!matched && length(groups) > 0) {
			for (let g_claim in groups) {
				for (let g_role in role.groups) {
					if (g_claim == g_role) {
						matched = true;
						break;
					}
				}
				if (matched) break;
			}
		}

		if (matched) {
			// Merge permissions with deduplication
			for (let r in role.read) {
				let exists = false;
				for (let pr in perms.read) { if (pr == r) { exists = true; break; } }
				if (!exists) push(perms.read, r);
			}
			for (let w in role.write) {
				let exists = false;
				for (let pw in perms.write) { if (pw == w) { exists = true; break; } }
				if (!exists) push(perms.write, w);
			}
			
			// Use the first matched role name as identity
			if (!perms.role_name) {
				perms.role_name = role.name;
			}
		}
	}

	return perms;
};
