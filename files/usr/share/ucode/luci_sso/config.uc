/**
 * Logic for loading and validating UCI configuration.
 */

/**
 * Loads the OIDC and User configuration from UCI.
 * Cross-references with /etc/config/rpcd to ensure mapped users exist.
 * 
 * @param {object} io - I/O provider
 * @returns {object} - The validated configuration object
 */
export function load(io) {
	let cursor = io.uci_cursor();

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
		die("CONFIG_ERROR: OIDC section 'default' missing in /etc/config/luci-sso");
	}

	if (oidc_cfg.enabled !== '1') {
		die("DISABLED");
	}

	// 2.1 HTTPS Enforcement
	let issuer = oidc_cfg.issuer_url;
	if (!issuer) {
		die("CONFIG_ERROR: issuer_url is mandatory");
	}

	if (substr(issuer, 0, 8) !== "https://") {
		die("CONFIG_ERROR: issuer_url must use HTTPS");
	}

	if (oidc_cfg.clock_tolerance == null || oidc_cfg.clock_tolerance == "") {
		die("CONFIG_ERROR: clock_tolerance option is mandatory");
	}

	let clock_tolerance = int(oidc_cfg.clock_tolerance);
	if (type(clock_tolerance) != "int") {
		die("CONFIG_ERROR: clock_tolerance must be an integer");
	}

	// 3. Load and Validate User Whitelists
	let user_mappings = [];
	cursor.foreach("luci-sso", "user", (s) => {
		let rpcd_user = s.rpcd_user;
		let emails = (type(s.email) == "array") ? s.email : (s.email ? [ s.email ] : []);

		if (!rpcd_user || !s.rpcd_password || length(emails) == 0) {
			if (rpcd_user) {
				io.log("warn", `Ignoring mapping for '${rpcd_user}': missing password or email list`);
			}
			return;
		}

		// Validation: Does this user exist in rpcd?
		if (!valid_rpcd_users[rpcd_user]) {
			io.log("warn", `Ignoring mapping for '${rpcd_user}': user not found in /etc/config/rpcd`);
			return;
		}

		push(user_mappings, {
			rpcd_user: rpcd_user,
			rpcd_password: s.rpcd_password,
			emails: emails
		});
	});

	return {
		issuer_url: oidc_cfg.issuer_url,
		internal_issuer_url: oidc_cfg.internal_issuer_url || oidc_cfg.issuer_url,
		client_id: oidc_cfg.client_id,
		client_secret: oidc_cfg.client_secret,
		redirect_uri: oidc_cfg.redirect_uri,
		clock_tolerance: clock_tolerance,
		user_mappings: user_mappings
	};
};
