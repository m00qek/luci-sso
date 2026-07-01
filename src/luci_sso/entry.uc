'use strict';

/**
 * CGI entry pipeline for luci-sso.
 *
 * Composes request parsing, configuration loading, routing, and response
 * rendering into a single `run(deps, web_deps)` orchestration. The executable
 * (`files/www/cgi-bin/luci-sso`) is a thin shell: it builds the real `deps` and
 * `web_deps` and calls `run`. Keeping the pipeline here (rather than inline in
 * the script) makes the wiring — including the SSO_DISABLED escape hatch and the
 * top-level crash handler — testable with faked deps.
 *
 * @module luci_sso_entry
 */

import * as web from 'luci_sso.web';
import * as config from 'luci_sso.config';
import * as router from 'luci_sso.router';

/**
 * Emits a router Result to the client: renders the response on success, or a
 * sanitised error page (HTTP status taken from `details.http_status`, default
 * 500) on failure.
 */
function emit(web_deps, res) {
	if (!res.ok) {
		let status = (type(res.details) == "object") ? res.details.http_status : 500;
		web.render_error(web_deps, res.error, status);
	} else {
		web.render(web_deps, res.data);
	}
};

/**
 * Runs the full request → config → route → render pipeline.
 *
 * @param {object} deps - The production dependency graph (see luci_sso.deps).
 * @param {object} web_deps - CGI I/O surface: { getenv, stdout, log }.
 */
export function run(deps, web_deps) {
	try {
		let res_req = web.request(web_deps);
		if (!res_req.ok) {
			let status = (type(res_req.details) == "object") ? res_req.details.http_status : 400;
			web.render_error(web_deps, res_req.error, status);
			return;
		}

		let req = res_req.data;

		// W2: allow ?action=enabled even when config loading fails with SSO_DISABLED,
		// so the login button can probe availability on an unconfigured router.
		let res_c = config.load({ uci: deps.uci, log: deps.log });
		if (!res_c.ok) {
			if (res_c.error == "SSO_DISABLED" && req.path == "/" && req.query.action == "enabled") {
				emit(web_deps, router.handle(deps, null, req));
				return;
			}
			web.render_error(web_deps, res_c.error, 500);
			return;
		}

		emit(web_deps, router.handle(deps, res_c.data, req));
	} catch (e) {
		web.error(web_deps, e);
	}
};
