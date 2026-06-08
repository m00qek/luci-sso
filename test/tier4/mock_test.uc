import { it, assert, truthy, falsy } from 'utest';
import * as mock from 'mock';

it('Meta: Mock DSL - Temporal file isolation', () => {
	let factory = mock.create();
	
	factory.with_files({ "/a": "1" }, (io1) => {
		assert.match("1", io1.read_file("/a"));
		
		factory.with_files({ "/b": "2" }, (io2) => {
			assert.match("2", io2.read_file("/b"));
			assert.match(falsy(), io2.read_file("/a"), "Should not leak from sibling scope");
		});
	});
});

it('Meta: Mock DSL - Explicit state accumulation via using()', () => {
	let factory = mock.create().with_files({ "/global": "ok" });
	
	factory.with_env({ "FOO": "bar" }, (io) => {
		let accumulated = factory.using(io).with_files({ "/local": "here" });
		
		accumulated.with_env({}, (io_final) => {
			assert.match("ok", io_final.read_file("/global"));
			assert.match("here", io_final.read_file("/local"));
			assert.match("bar", io_final.getenv("FOO"));
		});
	});
});

it('Meta: Mock DSL - Deep state accumulation layering', () => {
	let io = mock.create()
		.with_files({ "/f1": "1" })
		.with_env({ "E1": "1" })
		.with_ubus({ "U1": "1" })
		.with_responses({ "H1": "1" })
		.with_uci({ "P1": {} })
		.with_read_only((i) => i);

	assert.match("1", io.read_file("/f1"));
	assert.match("1", io.getenv("E1"));
});

it('Meta: Mock DSL - Read-only status persistence through inheritance', () => {
	let factory = mock.create().with_read_only();
	factory.with_files({}, (io) => {
		assert.match(falsy(), io.write_file("/test", "data"), "Root factory should be read-only");
		
		factory.using(io).with_env({}, (io2) => {
			assert.match(falsy(), io2.write_file("/test", "data"), "Inherited factory should remain read-only");
		});
	});
});

it('Meta: Mock DSL - Selective spy recording', () => {
	let factory = mock.create();
	factory.with_env({}, (io) => {
		io.log("warn", "ignored"); // Should not be in history
		
		let results = factory.using(io).spy((spying_io) => {
			spying_io.log("error", "captured");
		});
		
		assert.match(truthy(), results.called("log", "error", "captured"));
		assert.match(falsy(), results.called("log", "warn"), "Pre-spy logs MUST NOT be in history");
	});
});

it('Meta: Mock DSL - Argument matching for complex types', () => {
	let results = mock.create().spy((io) => {
		io.write_file("/a", "complex-data");
	});
	assert.match(truthy(), results.called("write_file", "/a", "complex-data"));
});

it('Meta: Mock DSL - Mandatory HTTPS enforcement', () => {
	mock.create().with_responses({}, (io) => {
		assert.match("HTTPS_REQUIRED", io.http_get("http://insecure.com").error);
		assert.match("HTTPS_REQUIRED", io.http_post("http://insecure.com").error);
	});
});

it('Meta: Mock DSL - Stdout capture via intercepted thunk', () => {
	let factory = mock.create();
	let out = factory.get_stdout((io) => {
		io.stdout.write("hello");
		io.stdout.write(" world");
	});
	assert.match("hello world", out);
});