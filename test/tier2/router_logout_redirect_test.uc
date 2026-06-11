import { it, assert, truthy } from 'utest';
import * as router from 'luci_sso.router';
import * as Result from 'luci_sso.result';
import * as mock from 'mock';

const TEST_POLICY = { allowed_algs: ["RS256"] };

function make_router_deps(io) {
	return {
		fs: {
			readfile:  (p)    => io.read_file(p),
			writefile: (p, d) => io.write_file(p, d),
			mkdir:     (p, m) => io.mkdir(p, m),
			unlink:    (p)    => io.remove(p),
			rename:    (o, n) => io.rename(o, n),
			stat:      (p)    => io.stat(p),
			chmod:     (p, m) => io.chmod(p, m),
			lsdir:     (p)    => io.lsdir(p),
			error:     ()     => io.fserror()
		},
		http:  { get: (url, opts) => io.http_get(url, opts), post: (url, opts) => io.http_post(url, opts) },
		ubus:  { call: (obj, method, args) => io.ubus_call(obj, method, args) },
		uci:   io.uci_cursor(),
		clock: { time: () => io.time(), sleep: (s) => io.sleep(s) },
		log:   io.log
	};
}

const MOCK_DISC_DOC = {
	issuer: "https://idp.com", 
	authorization_endpoint: "https://idp.com/auth",
	token_endpoint: "https://idp.com/token",
	jwks_uri: "https://idp.com/jwks",
	end_session_endpoint: "https://idp.com/logout"
};

it('router: logic - logout redirect derivation robustness (W3)', () => {
	let factory = mock.create()
		.with_ubus({ 
			"session:get": (args) => ({ values: { oidc_id_token: "hint", token: "csrf" } }),
			"session:destroy": {} 
		})
		.with_responses({
			"https://idp.com/.well-known/openid-configuration": { status: 200, body: MOCK_DISC_DOC }
		});

	// Test Case 1: Standard redirect_uri
	factory.with_env({}, (io) => {
		let config = { issuer_url: "https://idp.com", redirect_uri: "https://router.lan/cgi-bin/luci-sso/callback" };
		let req = { path: "/logout", query: { stoken: "csrf" }, cookies: { sysauth: "sid" } };
		let res = router.handle(make_router_deps(io), config, req, TEST_POLICY);
		assert.match(truthy(), res.ok);
		assert.match(truthy(), index(res.data.headers["Location"], "post_logout_redirect_uri=https%3A%2F%2Frouter.lan%2F") != -1);
	});

	// Test Case 2: Malformed redirect_uri (missing https://)
	// This shouldn't happen due to config.uc validation, but testing for robustness
	factory.with_env({}, (io) => {
		let config = { issuer_url: "https://idp.com", redirect_uri: "ftp://router.lan/callback" };
		let req = { path: "/logout", query: { stoken: "csrf" }, cookies: { sysauth: "sid" } };
		let res = router.handle(make_router_deps(io), config, req, TEST_POLICY);
		assert.match(truthy(), res.ok);
		// Correct logic (Audit W4): If regex fails, OMIT the parameter entirely rather than sending relative /
		assert.match(-1, index(res.data.headers["Location"], "post_logout_redirect_uri="), "Should OMIT post_logout_redirect_uri for invalid redirect_uri scheme");
	});
});
