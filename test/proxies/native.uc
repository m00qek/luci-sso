// Loaded via require() in ucode program mode — see proxy_base.uc for why `return` is used here.
//
// The utest shim manager knows this proxy as 'native', but the actual C extension is
// 'luci_sso.native'. get_real('native') therefore returns null. We load the real module
// by its full name inside create() so the fallback path works.
//
// ctx.base() iterates the real module via `for...in`, which does not enumerate C extension
// functions. We build the proxy manually with a named wrap() helper to avoid any
// closure-in-loop issues.
return {
	api: ['random', 'sha256', 'hmac_sha256', 'verify_rs256', 'verify_es256', 'jwk_rsa_to_pem', 'jwk_ec_p256_to_pem'],

	create: function(name, real, ctx) {
		let nat = real;
		if (!nat) {
			try { nat = require('luci_sso.native'); } catch(e) {}
		}

		let wrap = function(fn_name, fn) {
			return function(...args) {
				ctx.record_call(fn_name, args);
				let override = ctx.get_behavior(fn_name);
				if (override) return override(...args);
				if (ctx.is_strict()) die(sprintf("strict mock: 'native.%s' called with unmocked", fn_name));
				return fn(...args);
			};
		};

		return {
			random:             wrap('random',             nat ? nat.random             : null),
			sha256:             wrap('sha256',             nat ? nat.sha256             : null),
			hmac_sha256:        wrap('hmac_sha256',        nat ? nat.hmac_sha256        : null),
			verify_rs256:       wrap('verify_rs256',       nat ? nat.verify_rs256       : null),
			verify_es256:       wrap('verify_es256',       nat ? nat.verify_es256       : null),
			jwk_rsa_to_pem:     wrap('jwk_rsa_to_pem',    nat ? nat.jwk_rsa_to_pem    : null),
			jwk_ec_p256_to_pem: wrap('jwk_ec_p256_to_pem', nat ? nat.jwk_ec_p256_to_pem : null),
		};
	}
};
