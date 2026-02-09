import { test, assert, assert_eq } from 'testing';
import * as mock from 'mock';

test('Meta: Mock DSL - Temporal file isolation', () => {
	let factory = mock.create();
	
	factory.with_files({ "/a": "1" }, (io1) => {
		assert_eq(io1.read_file("/a"), "1");
		
		factory.with_files({ "/b": "2" }, (io2) => {
			assert_eq(io2.read_file("/b"), "2");
			assert(!io2.read_file("/a"), "Should not leak from sibling scope");
		});
	});
});

test('Meta: Mock DSL - Explicit state accumulation via using()', () => {
	let factory = mock.create().with_files({ "/global": "ok" });
	
	factory.with_env({ "FOO": "bar" }, (io) => {
		let accumulated = factory.using(io).with_files({ "/local": "here" });
		
		accumulated.with_env({}, (io_final) => {
			assert_eq(io_final.read_file("/global"), "ok");
			assert_eq(io_final.read_file("/local"), "here");
			assert_eq(io_final.getenv("FOO"), "bar");
		});
	});
});

test('Meta: Mock DSL - Deep state accumulation layering', () => {
	let io = mock.create()
		.with_files({ "/f1": "1" })
		.with_env({ "E1": "1" })
		.with_ubus({ "U1": "1" })
		.with_responses({ "H1": "1" })
		.with_uci({ "P1": {} })
		.with_read_only((i) => i);

	assert_eq(io.read_file("/f1"), "1");
	assert_eq(io.getenv("E1"), "1");
});

test('Meta: Mock DSL - Read-only status persistence through inheritance', () => {
	let factory = mock.create().with_read_only();
	factory.with_files({}, (io) => {
		assert(!io.write_file("/test", "data"), "Root factory should be read-only");
		
		factory.using(io).with_env({}, (io2) => {
			assert(!io2.write_file("/test", "data"), "Inherited factory should remain read-only");
		});
	});
});

test('Meta: Mock DSL - Selective spy recording', () => {
	let factory = mock.create();
	factory.with_env({}, (io) => {
		io.log("warn", "ignored"); // Should not be in history
		
		let results = factory.using(io).spy((spying_io) => {
			spying_io.log("error", "captured");
		});
		
		assert(results.called("log", "error", "captured"));
		assert(!results.called("log", "warn"), "Pre-spy logs MUST NOT be in history");
	});
});

test('Meta: Mock DSL - Argument matching for complex types', () => {
	let results = mock.create().spy((io) => {
		io.write_file("/a", "complex-data");
	});
	assert(results.called("write_file", "/a", "complex-data"));
});

test('Meta: Mock DSL - Mandatory HTTPS enforcement', () => {
	mock.create().with_responses({}, (io) => {
		assert_eq(io.http_get("http://insecure.com").error, "HTTPS_REQUIRED");
		assert_eq(io.http_post("http://insecure.com").error, "HTTPS_REQUIRED");
	});
});

test('Meta: Mock DSL - Stdout capture via intercepted thunk', () => {
	let factory = mock.create();
	let out = factory.get_stdout((io) => {
		io.stdout.write("hello");
		io.stdout.write(" world");
	});
	assert_eq(out, "hello world");
});