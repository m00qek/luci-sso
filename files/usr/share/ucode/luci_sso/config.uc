/**
 * Logic for loading and validating UCI configuration.
 */

/**
 * Loads the OIDC and User configuration from UCI.
 * Cross-references with /etc/config/rpcd to ensure mapped users exist.
 * 
 * @param {object} cursor - UCI cursor
 * @param {object} io - I/O provider (for logging)
 * @returns {object} - Result Object {ok, data/error}
 */
export function load(cursor, io) {
	if (!cursor || type(cursor.get_all) != "function") {
		die("CONTRACT_VIOLATION: config.load expects a UCI cursor");
	}

	// 1. Load RPCD users to build a validation set
	let valid_rpcd_users = {};
	cursor.foreach("rpcd", "login", (s) => {
		if (s.username) {
			valid_rpcd_users[s.username] = true;
		}
	});

	// 2. Load OIDC Provider Settings
	let oidc_cfg = cursor.get_all("luci-sso", "default");
	if (!oidc_cfg || oidc_cfg[".type"] !== "oidc") {
		return { ok: false, error: "CONFIG_NOT_FOUND", details: "OIDC section 'default' missing" };
	}

	if (oidc_cfg.enabled !== '1') {
		return { ok: false, error: "DISABLED" };
	}

	// 2.1 HTTPS Enforcement
	let issuer = oidc_cfg.issuer_url;
	if (!issuer) {
		return { ok: false, error: "MISSING_ISSUER_URL" };
	}

	let is_localhost = (index(issuer, "://localhost") > 0 || index(issuer, "://127.0.0.1") > 0);
	if (substr(issuer, 0, 8) !== "https://" && !is_localhost) {
		return { ok: false, error: "INSECURE_ISSUER", details: "issuer_url must use HTTPS" };
	}

	let clock_tolerance = int(oidc_cfg.clock_tolerance);
	if (clock_tolerance == null) {
		return { ok: false, error: "MISSING_CLOCK_TOLERANCE", details: "clock_tolerance option is mandatory" };
	}

	// 3. Load and Validate User Whitelists
	let user_mappings = [];
	cursor.foreach("luci-sso", "user", (s) => {
		let rpcd_user = s.rpcd_user;
		let emails = (type(s.email) == "array") ? s.email : (s.email ? [ s.email ] : []);

		if (!rpcd_user || !s.rpcd_password || length(emails) == 0) {
			if (io && io.log && rpcd_user) {
				io.log("warn", `Ignoring mapping for '${rpcd_user}': missing password or email list`);
			}
			return;
		}

		// Validation: Does this user exist in rpcd?
		if (!valid_rpcd_users[rpcd_user]) {
			if (io && io.log) {
				io.log("warn", `Ignoring mapping for '${rpcd_user}': user not found in /etc/config/rpcd`);
			}
			return;
		}

		push(user_mappings, {
			rpcd_user: rpcd_user,
			rpcd_password: s.rpcd_password,
			emails: emails
		});
	});

	return {
		ok: true,
		data: {
			issuer_url: oidc_cfg.issuer_url,
			internal_issuer_url: oidc_cfg.internal_issuer_url || oidc_cfg.issuer_url,
			client_id: oidc_cfg.client_id,
			client_secret: oidc_cfg.client_secret,
			redirect_uri: oidc_cfg.redirect_uri,
			clock_tolerance: clock_tolerance,
			user_mappings: user_mappings
		}
	};
};