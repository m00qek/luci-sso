// Loaded via require() in ucode program mode — see proxy_base.uc for why `return` is used here.
return {
	api: ['random', 'sha256', 'hmac_sha256', 'verify_rs256', 'verify_es256', 'jwk_rsa_to_pem', 'jwk_ec_p256_to_pem'],
	create: function(name, real, ctx) {
		let proxy = ctx.base();

		proxy.random = function(...args) {
			ctx.record_call('random', args);
			let f = ctx.get_behavior('random');
			if (f) return f(...args);
			if (ctx.is_strict()) die("strict mock: 'native.random' is not mocked");
			return real ? real.random(...args) : null;
		};

		proxy.sha256 = function(...args) {
			ctx.record_call('sha256', args);
			let f = ctx.get_behavior('sha256');
			if (f) return f(...args);
			if (ctx.is_strict()) die("strict mock: 'native.sha256' is not mocked");
			return real ? real.sha256(...args) : null;
		};

		proxy.hmac_sha256 = function(...args) {
			ctx.record_call('hmac_sha256', args);
			let f = ctx.get_behavior('hmac_sha256');
			if (f) return f(...args);
			if (ctx.is_strict()) die("strict mock: 'native.hmac_sha256' is not mocked");
			return real ? real.hmac_sha256(...args) : null;
		};

		proxy.verify_rs256 = function(...args) {
			ctx.record_call('verify_rs256', args);
			let f = ctx.get_behavior('verify_rs256');
			if (f) return f(...args);
			if (ctx.is_strict()) die("strict mock: 'native.verify_rs256' is not mocked");
			return real ? real.verify_rs256(...args) : null;
		};

		proxy.verify_es256 = function(...args) {
			ctx.record_call('verify_es256', args);
			let f = ctx.get_behavior('verify_es256');
			if (f) return f(...args);
			if (ctx.is_strict()) die("strict mock: 'native.verify_es256' is not mocked");
			return real ? real.verify_es256(...args) : null;
		};

		proxy.jwk_rsa_to_pem = function(...args) {
			ctx.record_call('jwk_rsa_to_pem', args);
			let f = ctx.get_behavior('jwk_rsa_to_pem');
			if (f) return f(...args);
			if (ctx.is_strict()) die("strict mock: 'native.jwk_rsa_to_pem' is not mocked");
			return real ? real.jwk_rsa_to_pem(...args) : null;
		};

		proxy.jwk_ec_p256_to_pem = function(...args) {
			ctx.record_call('jwk_ec_p256_to_pem', args);
			let f = ctx.get_behavior('jwk_ec_p256_to_pem');
			if (f) return f(...args);
			if (ctx.is_strict()) die("strict mock: 'native.jwk_ec_p256_to_pem' is not mocked");
			return real ? real.jwk_ec_p256_to_pem(...args) : null;
		};

		return proxy;
	}
};
