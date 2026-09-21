'use strict';

/**
 * Wall-clock and sleep component backed by the uloop event loop.
 *
 * Grouping `time()` and `sleep()` together lets tests control both through a
 * single dependency: the utest uloop proxy makes `sleep()` synchronous
 * (timers fire immediately via `run()`), and `time_fn` can be overridden
 * for deterministic timestamps.
 *
 * @module luci_sso_components_clock
 * @typedef {{time: () => int, sleep: (seconds: float) => void}} Clock
 */

/**
 * Creates a Clock backed by the given uloop module.
 *
 * @param {module:uloop} uloop uloop module (or utest proxy) used to drive the sleep timer.
 * @param {function} [time_fn] Timestamp source; defaults to the built-in `time()`.
 * @returns {Clock}
 */
export function create(uloop, time_fn) {
	time_fn = time_fn || time;

	return {
		time: time_fn,

		sleep: function(seconds) {
			if ((type(seconds) !== "int" && type(seconds) !== "double") || seconds < 0 || seconds > 30)
				die("CONTRACT_VIOLATION: sleep expects a number in [0, 30]");

			uloop.init();
			uloop.timer(seconds * 1000, () => uloop.end());
			uloop.run();
		}
	};
};
