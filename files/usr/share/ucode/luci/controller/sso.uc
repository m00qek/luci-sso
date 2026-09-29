// luci-sso: LuCI's "Log out" for sessions created through SSO.
//
// /usr/share/luci/menu.d/luci-sso-logout.json points LuCI's own admin/logout
// menu entry at action_logout below. The dispatcher calls it like any
// controller function, with ctx, http, ubus and dispatcher as globals.
//
// A session that luci-sso created has the username `sso:<role>`, the username
// of the role's rpcd login entry. Those are sent to luci-sso's /logout
// endpoint, which destroys the session, clears the session cookies at both
// paths and forwards the browser to the IdP's end_session_endpoint
// (RP-Initiated Logout), so the IdP session ends too. Every other session, and
// any session that cannot be looked up, gets LuCI's own logout, called
// unchanged. The `oidc_user` value is not the test: it holds the user's email,
// which a user matched by group whose IdP sends no email does not have.

"use strict";

import { urlencode } from 'lucihttp';
import { role_of } from 'luci_sso.rpcd_login';

function is_sso_session(sid) {
	const reply = ubus.call("session", "get", { ubus_rpc_session: sid });
	return type(reply?.values) == "object" && role_of(reply.values.username) != null;
}

return {
	action_logout: function() {
		const sid = ctx.authsession;
		const token = ctx.authtoken;

		if (sid && token && is_sso_session(sid)) {
			http.redirect(`/cgi-bin/luci-sso/logout?stoken=${urlencode(token, 1)}`);
			return;
		}

		// Nested calls see the dispatcher's globals, so LuCI's own function
		// runs exactly as if the menu still pointed at it.
		require("luci.controller.admin.index").action_logout();
	}
};
