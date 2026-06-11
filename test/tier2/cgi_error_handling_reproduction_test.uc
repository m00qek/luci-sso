import { it, assert, truthy, falsy } from 'utest';
import * as web_mod from 'luci_sso.web';
import * as router from 'luci_sso.router';
import { with_context } from 'context';

it('cgi: reproduction - missing Result.ok check (W1)', () => {
	let config = {
		enabled: true,
		client_id: "test",
		issuer_url: "https://idp.test",
		redirect_uri: "https://luci.test/callback"
	};

	let stdout_buf = "";
	let stdout = { write: (s) => { stdout_buf += s; }, flush: () => {} };

	let getenv = (k) => {
		let env = { PATH_INFO: "/invalid-path", HTTP_HOST: "luci.test" };
		return env[k] || null;
	};

	with_context({
		fs:    { data: {} },
		clock: { data: { now: 1516239022 } }
	}, (deps) => {
		let web_deps = { getenv, stdout, log: deps.log };

		let res_req = web_mod.request(web_deps);
		assert.match(truthy(), res_req.ok);
		let req = res_req.data;

		let res_router = router.handle(deps, config, req);
		assert.match(falsy(), res_router.ok, "Router should return error for invalid path");

		let rendered_error = false;
		res_router = router.handle(deps, config, req);
		if (!res_router.ok) {
			let status = (type(res_router.details) == "object") ? res_router.details.http_status : 500;
			web_mod.render_error(web_deps, res_router.error, status);
			rendered_error = true;
		} else {
			web_mod.render(web_deps, res_router.data);
		}

		assert.match(truthy(), rendered_error, "Should have rendered an error response");
	});
});
