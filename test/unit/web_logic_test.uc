import { test, assert, assert_eq } from 'testing';
import * as web from 'luci_sso.web';
import * as mock from 'mock';

// =============================================================================
// Tier 2: Web Integration Logic (Platinum Suite)
// =============================================================================

test('LOGIC: Web - Request Query Parsing', () => {
	let mocked = mock.create();
	mocked.with_env({
		QUERY_STRING: "redirect_uri=http%3A%2F%2Floc%2F&state=abc+123&empty="
	}, (io) => {
		let req = web.request(io);
		assert_eq(req.query.redirect_uri, "http://loc/", "Should decode colon and slash");
		assert_eq(req.query.state, "abc 123", "Should decode plus as space");
		assert_eq(req.query.empty, "", "Should handle empty value");
	});
});

test('LOGIC: Web - Request Cookie Parsing', () => {
	let mocked = mock.create();
	mocked.with_env({
		HTTP_COOKIE: 'luci_sso_state="eyJhbGc.abc"; Path=/; luci_sso_session=token123'
	}, (io) => {
		let req = web.request(io);
		assert_eq(req.cookies.luci_sso_state, "eyJhbGc.abc", "Should strip double quotes");
		assert_eq(req.cookies.luci_sso_session, "token123", "Should parse multiple cookies");
	});
});

test('LOGIC: Web - Request Context Full Integration', () => {
	let mocked = mock.create();
	mocked.with_env({
		PATH_INFO: "/callback",
		QUERY_STRING: "code=123",
		HTTP_COOKIE: "c=v"
	}, (io) => {
		let req = web.request(io);
		assert_eq(req.path, "/callback");
		assert_eq(req.query.code, "123");
		assert_eq(req.cookies.c, "v");
	});
});

test('LOGIC: Web - Enforce Limits', () => {
	let mocked = mock.create();

    // 1. Length Limit (16KB)
	let massive = "";
	for (let i = 0; i < 2000; i++) massive += "key=value&";
	
	mocked.with_env({ QUERY_STRING: massive }, (io) => {
		let req = web.request(io);
		assert_eq(length(req.query), 0, "Should reject massive parameter string");
	});

    // 2. Count Limit (100)
	let many = "";
	for (let i = 0; i < 150; i++) many += `k${i}=v&`;
	
	mocked.with_env({ QUERY_STRING: many }, (io) => {
		let req = web.request(io);
		assert_eq(length(req.query), 100, "Should limit parameter count to exactly 100");
	});
});

test('LOGIC: Web - Resilience against Malformed Input', () => {
	let mocked = mock.create();
	
	mocked.with_env({
		QUERY_STRING: "key_with_no_value&==&valid=yes",
		HTTP_COOKIE: "broken; ; also_broken=; valid=yes"
	}, (io) => {
		let req = web.request(io);
		
		// Query: "key_with_no_value" should exist but be null/empty, "valid" should be "yes"
		assert_eq(req.query.valid, "yes");
		assert(req.query.key_with_no_value == null || req.query.key_with_no_value == "");
		
		// Cookies: "valid" should be "yes", others should not crash the parser
		assert_eq(req.cookies.valid, "yes");
	});
});

test('LOGIC: Web - Render 302 Redirect', () => {
	let mocked = mock.create();
	let res = {
		status: 302,
		headers: {
			"Location": "https://idp.com/auth",
			"Set-Cookie": "c=v"
		}
	};
	
	let buf = mocked.get_stdout((io) => {
		web.render(io, res);
	});
	
	assert(index(buf, "Status: 302 Found\n") >= 0);
	assert(index(buf, "Location: https://idp.com/auth\n") >= 0);
	assert(index(buf, "Set-Cookie: c=v\n") >= 0);
	assert(index(buf, "Content-Type: text/html\n") >= 0);
	assert(index(buf, "window.location.href=\"https://idp.com/auth\"") >= 0);
});

test('LOGIC: Web - Render Resilience (Null headers/body)', () => {
	let mocked = mock.create();
	
	let buf = mocked.get_stdout((io) => {
		web.render(io, { status: 200 });
	});
	
	assert(length(buf) >= 1, "Should have produced some output");
});

test('LOGIC: Web - Render Multiple Cookies', () => {
	let mocked = mock.create();
	let res = {
		status: 200,
		headers: {
			"Set-Cookie": ["c1=v1", "c2=v2"]
		},
		body: "OK"
	};
	
	let buf = mocked.get_stdout((io) => {
		web.render(io, res);
	});
	
	assert(index(buf, "Set-Cookie: c1=v1\n") >= 0);
	assert(index(buf, "Set-Cookie: c2=v2\n") >= 0);
	assert(index(buf, "\n\nOK") >= 0);
});

test('LOGIC: Web - Render Error 500', () => {
	let mocked = mock.create();
	
	let buf = mocked.get_stdout((io) => {
		web.error(io, "Explosion!");
	});
	
	assert(index(buf, "Status: 500 Internal Server Error\n") >= 0);
	assert(index(buf, "Content-Type: text/plain\n") >= 0);
	assert(index(buf, "Router Crash: Explosion!") >= 0);
});

test('LOGIC: Web - Handle Missing/Invalid Env', () => {
	let mocked = mock.create();
	mocked.with_env({}, (io) => {
		let req = web.request(io);
		assert_eq(req.path, "/");
		assert_eq(length(req.query), 0);
		assert_eq(length(req.cookies), 0);
	});
});