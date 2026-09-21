// Loaded via require() in ucode program mode — see proxy_base.uc for why `return` is used here.
return {
	api: ['time', 'sleep'],

	create: function(name, real, ctx) {
		let proxy = ctx.base();

		proxy.create = function(uloop, time_fn) { return proxy; };

		proxy.time = function() {
			ctx.record_call('time', []);
			let f = ctx.get_behavior('time');
			if (f) return f();
			let t = ctx.get_data('now');
			return (t !== null) ? t : 0;
		};

		proxy.sleep = function(seconds) {
			ctx.record_call('sleep', [seconds]);
			let f = ctx.get_behavior('sleep');
			if (f) return f(seconds);
		};

		return proxy;
	}
};
