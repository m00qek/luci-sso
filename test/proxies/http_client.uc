// Loaded via require() in ucode program mode — see proxy_base.uc for why `return` is used here.
// Note: require() runs files as program-mode scripts, so `import` / `export` are not available.
function ok(data)          { return { ok: true,  data: data }; }
function err(code, detail) { return { ok: false, error: code, detail: detail }; }

return {
	api: ['get', 'post'],

	create: function(name, real, ctx) {
		let proxy = ctx.base();

		let make_response = function(url) {
			let entry = ctx.get_data(url);
			if (entry == null) {
				if (ctx.is_strict()) die("strict http mock: unmocked URL: " + url);
				return err("HTTP_REQUEST_FAILED", "HTTP_NOT_FOUND");
			}
			if (entry.error)
				return err("HTTP_REQUEST_FAILED", entry.error);
			let body = (type(entry.body) == "object") ? sprintf("%J", entry.body) : (entry.body || "");
			return ok({ status: entry.status || 200, body: body });
		};

		proxy.create = function(uclient, uloop, fs) { return proxy; };

		proxy.get = function(url, opts) {
			ctx.record_call('get', [url, opts]);
			let f = ctx.get_behavior('get');
			if (f) return f(url, opts);
			return make_response(url);
		};

		proxy.post = function(url, opts) {
			ctx.record_call('post', [url, opts]);
			let f = ctx.get_behavior('post');
			if (f) return f(url, opts);
			return make_response(url);
		};

		return proxy;
	}
};
