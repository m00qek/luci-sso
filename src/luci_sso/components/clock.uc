'use strict';

/**
 * Creates a clock component backed by the given uloop module.
 *
 * Grouping time() and sleep() together means tests can control both via a
 * single dep: the uloop proxy makes sleep() synchronous (run() fires timers
 * immediately), and time_fn can be overridden for deterministic timestamps.
 *
 * @param {object} uloop    - The uloop module (or a utest proxy of it)
 * @param {function} [time_fn] - Override for time(); defaults to the builtin
 * @returns {{ time, sleep }}
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
