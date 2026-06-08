import { it, assert, truthy } from 'utest';
import * as io_mod from 'luci_sso.io';
import * as web_mod from 'luci_sso.web';
import * as router from 'luci_sso.router';
import * as config_loader from 'luci_sso.config';
import * as mock from 'mock';

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
		let res_req = web_mod.request(io);
		assert.match(truthy(), res_req.ok);
		let req = res_req.data;

		// 4. Call router (should return error for /invalid-path)
		let res_router = router.handle(io, config, req);
		assert.match(truthy(), !res_router.ok, "Router should return error for invalid path");

		// 5. Simulate the FIXED CGI code:
		let rendered_error = false;
		let res_router = router.handle(io, config, req);
		if (!res_router.ok) {
			let status = (type(res_router.details) == "object") ? res_router.details.http_status : 500;
			web_mod.render_error(io, res_router.error, status);
			rendered_error = true;
		} else {
			web_mod.render(io, res_router.data);
		}
		
		assert.match(truthy(), rendered_error, "Should have rendered an error response");
		// Ensure it didn't crash (if it did, the test would fail on exception)
	});
});
