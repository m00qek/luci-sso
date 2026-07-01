// Loaded via require() in ucode program mode — see proxy_base.uc for why `return` is used here.
//
// Mocking precedence for every function, in order:
//   1. behavior: { <fn>: (...args) => ... }  — a stub function (input-dependent / call-counting)
//   2. data:     { <fn>: <value> }            — a canned return value (preferred; may be null/false)
//   3. strict    → die on any unmocked call
//   4. otherwise → forward to the real extension (or null if it could not load)
//
// The `data` channel is keyed by function name, e.g. data: { sha256: <digest>,
// random: <bytes>, verify_rs256: true }. Prefer `data:` over `behavior:`.
return {
	api: ['random', 'sha256', 'hmac_sha256', 'verify_rs256', 'verify_es256', 'jwk_rsa_to_pem', 'jwk_ec_p256_to_pem'],
	create: function(name, real, ctx) {
		let proxy = ctx.base();

		function resolve(fn_name, args, fallback) {
			let f = ctx.get_behavior(fn_name);
			if (f) return f(...args);
			if (ctx.has_data(fn_name)) return ctx.get_data(fn_name);
			if (ctx.is_strict()) die(sprintf("strict mock: 'native.%s' is not mocked", fn_name));
			return real ? real[fn_name](...args) : fallback;
		}

		proxy.random = function(...args) {
			ctx.record_call('random', args);
			return resolve('random', args, null);
		};

		proxy.sha256 = function(...args) {
			ctx.record_call('sha256', args);
			return resolve('sha256', args, null);
		};

		proxy.hmac_sha256 = function(...args) {
			ctx.record_call('hmac_sha256', args);
			return resolve('hmac_sha256', args, null);
		};

		proxy.verify_rs256 = function(...args) {
			ctx.record_call('verify_rs256', args);
			return resolve('verify_rs256', args, null);
		};

		proxy.verify_es256 = function(...args) {
			ctx.record_call('verify_es256', args);
			return resolve('verify_es256', args, null);
		};

		proxy.jwk_rsa_to_pem = function(...args) {
			ctx.record_call('jwk_rsa_to_pem', args);
			return resolve('jwk_rsa_to_pem', args, null);
		};

		proxy.jwk_ec_p256_to_pem = function(...args) {
			ctx.record_call('jwk_ec_p256_to_pem', args);
			return resolve('jwk_ec_p256_to_pem', args, null);
		};

		return proxy;
	}
};
