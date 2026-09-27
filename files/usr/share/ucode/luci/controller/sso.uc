// luci-sso: LuCI's "Log out" for sessions created through SSO.
//
// /usr/share/luci/menu.d/luci-sso-logout.json points LuCI's own admin/logout
// menu entry at action_logout below. The dispatcher calls it like any
// controller function, with ctx, http, ubus and dispatcher as globals.
//
// A session that luci-sso created carries an `oidc_user` value. Those are
// sent to luci-sso's /logout endpoint, which destroys the session, clears the
// session cookies at both paths and forwards the browser to the IdP's
// end_session_endpoint (RP-Initiated Logout), so the IdP session ends too.
// Every other session, and any session that cannot be looked up, gets LuCI's
// own logout, called unchanged.

'use strict';

import { urlencode } from 'lucihttp';

function is_sso_session(sid) {
	const reply = ubus.call('session', 'get', { ubus_rpc_session: sid });
	return type(reply?.values) == 'object' && !!reply.values.oidc_user;
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
		require('luci.controller.admin.index').action_logout();
	}
};
