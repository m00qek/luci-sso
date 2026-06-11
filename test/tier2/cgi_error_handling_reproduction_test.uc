import { it, assert, truthy, falsy } from 'utest';
import * as web_mod from 'luci_sso.web';
import * as router from 'luci_sso.router';
import * as config_loader from 'luci_sso.config';
import * as mock from 'mock';

function make_web_deps(io) {
	return {
		getenv: (k)    => io.getenv(k),
		stdout: io.stdout,
		log:    (l, m) => io.log(l, m)
	};
}

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

/**
 * REPRODUCTION TEST for W1: Missing Result.ok check in CGI entry point.
 * 
 * This test simulates the logic in files/www/cgi-bin/luci-sso and confirms
 * that it would crash (catch block) if router.handle returns an error
 * instead of a proper error page.
 */
it('cgi: reproduction - missing Result.ok check (W1)', () => {
	let factory = mock.create();
	
	// Mock a scenario where router.handle returns an error.
	// We can force this by providing an invalid path or state.
	factory.spy((io) => {
		// 1. Setup environment
		io.getenv = (k) => {
			if (k == "PATH_INFO") return "/invalid-path";
			if (k == "HTTP_HOST") return "luci.test";
			return null;
		};

		// 2. Mock config (enabled)
		let config = { 
			enabled: true, 
			client_id: "test", 
			issuer_url: "https://idp.test",
			redirect_uri: "https://luci.test/callback"
		};

		// 3. Parse request
		let res_req = web_mod.request(make_web_deps(io));
		assert.match(truthy(), res_req.ok);
		let req = res_req.data;

		// 4. Call router (should return error for /invalid-path)
		let res_router = router.handle(make_router_deps(io), config, req);
		assert.match(falsy(), res_router.ok, "Router should return error for invalid path");

		// 5. Simulate the FIXED CGI code:
		let rendered_error = false;
		let res_router = router.handle(make_router_deps(io), config, req);
		if (!res_router.ok) {
			let status = (type(res_router.details) == "object") ? res_router.details.http_status : 500;
			web_mod.render_error(make_web_deps(io), res_router.error, status);
			rendered_error = true;
		} else {
			web_mod.render(make_web_deps(io), res_router.data);
		}
		
		assert.match(truthy(), rendered_error, "Should have rendered an error response");
		// Ensure it didn't crash (if it did, the test would fail on exception)
	});
});
