// Loaded via require() in ucode program mode — see proxy_base.uc for why `return` is used here.
const Result = require('luci_sso.result');

return {
	api: ['get', 'post'],

	create: function(name, real, ctx) {
		let proxy = ctx.base();

		let make_response = function(url) {
			let entry = ctx.get_data(url);
			if (entry == null) {
				if (ctx.is_strict()) die("strict http mock: unmocked URL: " + url);
				return Result.err("HTTP_REQUEST_FAILED", "HTTP_NOT_FOUND");
			}
			if (entry.error)
				return Result.err("HTTP_REQUEST_FAILED", entry.error);
			let body = (type(entry.body) == "object") ? sprintf("%J", entry.body) : (entry.body || "");
			return Result.ok({ status: entry.status || 200, body: body });
		};

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
