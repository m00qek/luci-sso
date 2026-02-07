import { assert, assert_eq, when, then } from 'testing';
import * as mock from 'mock';

when("using the Platinum Mock DSL", () => {
	let mocked = mock.create();

	then("it should enforce temporal file isolation", () => {
		mocked.with_files({ "/a": 1 }, (io) => {
			assert_eq(io.read_file("/a"), 1);
		});
		
		mocked.with_files({}, (io) => {
			assert_eq(io.read_file("/a"), null);
		});
	});

	then("it should support explicit state accumulation via using()", () => {
		mocked.with_files({ "/file": "exists" }, (io) => {
			// This branch inherits files and adds env
			mocked.using(io).with_env({ KEY: "val" }, (io_nested) => {
				assert_eq(io_nested.read_file("/file"), "exists");
				assert_eq(io_nested.getenv("KEY"), "val");
			});

			// This branch does NOT join, so it stays pure
			mocked.with_env({ KEY: "pure" }, (io_pure) => {
				assert_eq(io_pure.read_file("/file"), null);
				assert_eq(io_pure.getenv("KEY"), "pure");
			});
		});
	});

	then("it should support deep state accumulation layering", () => {
		mocked.with_files({ "/a": 1 }, (io1) => {
			mocked.using(io1).with_files({ "/b": 2 }, (io2) => {
				mocked.using(io2).with_files({ "/c": 3 }, (io3) => {
					assert_eq(io3.read_file("/a"), 1);
					assert_eq(io3.read_file("/b"), 2);
					assert_eq(io3.read_file("/c"), 3);
				});
				assert_eq(io2.read_file("/c"), null, "Parent should not see inner state");
			});
		});
	});

	then("it should persist read-only status through inheritance", () => {
		mocked.with_read_only((io_ro) => {
			assert_eq(io_ro.write_file("/a", "b"), false);
			
			mocked.using(io_ro).with_env({ K: "V" }, (io_nested) => {
				assert_eq(io_nested.write_file("/a", "b"), false, "RO status must be inherited");
				assert_eq(io_nested.getenv("K"), "V");
			});
		});
	});

	then("it should only record when spy() is active", () => {
		mocked.with_env({}, (io) => {
			io.log("warn", "ignored");
		});

		let data = mocked.spy((io) => {
			io.log("error", "captured");
			io.ubus_call("session", "login", { u: "root" });
		});

		assert(data.called("log", "error"), "Should capture log");
		assert(!data.called("log", "warn"), "Should not have captured previous logs");
		assert(data.called("ubus", "session", "login"), "Should capture ubus");
	});

	then("it should support argument matching for complex types", () => {
		let data = mocked.spy((io) => {
			io.ubus_call("obj", "method", { complex: { nested: true } });
		});

		// Base predicate only matches positional arguments
		assert(data.called("ubus", "obj", "method"));
	});

	then("it should support capturing stdout via intercepted thunk", () => {
		let buf = mocked.get_stdout((io) => {
			io.stdout.write("hello ");
			io.stdout.write("world");
		});

		assert_eq(buf, "hello world");
	});
});
