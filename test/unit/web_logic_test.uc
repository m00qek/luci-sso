import { test, assert, assert_eq } from 'testing';
import * as web from 'luci_sso.web';

/**
 * Creates a mock IO provider for web logic testing.
 */
function create_mock_io(env, stdout) {
	return {
		_env: env || {},
		getenv: function(k) { return this._env[k]; },
		stdout: stdout || { write: () => {}, flush: () => {} },
		log: () => {}
	};
}

/**
 * Creates a mock stdout that captures all writes.
 */
function create_mock_stdout() {
	return {
		_buf: "",
		write: function(s) { this._buf += s; },
		flush: function() { }
	};
}

// =============================================================================
// Tier 2: Web Integration Logic
// =============================================================================

test('LOGIC: Web - Request Query Parsing', () => {
	let io = create_mock_io({
		QUERY_STRING: "redirect_uri=http%3A%2F%2Floc%2F&state=abc+123&empty="
	});
	
	let req = web.request(io);
	assert_eq(req.query.redirect_uri, "http://loc/", "Should decode colon and slash");
	assert_eq(req.query.state, "abc 123", "Should decode plus as space");
	assert_eq(req.query.empty, "", "Should handle empty value");
});

test('LOGIC: Web - Request Cookie Parsing', () => {
	let io = create_mock_io({
		HTTP_COOKIE: 'luci_sso_state="eyJhbGc.abc"; Path=/; luci_sso_session=token123'
	});
	
	let req = web.request(io);
	assert_eq(req.cookies.luci_sso_state, "eyJhbGc.abc", "Should strip double quotes");
	assert_eq(req.cookies.luci_sso_session, "token123", "Should parse multiple cookies");
});

test('LOGIC: Web - Request Context Full Integration', () => {
	let io = create_mock_io({
		PATH_INFO: "/callback",
		QUERY_STRING: "code=123",
		HTTP_COOKIE: "c=v"
	});
	
	let req = web.request(io);
	assert_eq(req.path, "/callback");
	assert_eq(req.query.code, "123");
	assert_eq(req.cookies.c, "v");
});

test('LOGIC: Web - Enforce Limits', () => {
    // 1. Length Limit (16KB)
	let massive = "";
	for (let i = 0; i < 2000; i++) massive += "key=value&";
	let io = create_mock_io({ QUERY_STRING: massive });
	
	let req = web.request(io);
	assert_eq(length(req.query), 0, "Should reject massive parameter string");

    // 2. Count Limit (100)
	let many = "";
	for (let i = 0; i < 150; i++) many += `k${i}=v&`;
	io = create_mock_io({ QUERY_STRING: many });
	
	req = web.request(io);
	assert_eq(length(req.query), 100, "Should limit parameter count to 100");
});

test('LOGIC: Web - Render 302 Redirect', () => {
	let stdout = create_mock_stdout();
	let io = create_mock_io({}, stdout);
	
	let res = {
		status: 302,
		headers: {
			"Location": "https://idp.com/auth",
			"Set-Cookie": "c=v"
		}
	};
	
	web.render(io, res);
	
	assert(index(stdout._buf, "Status: 302 Found\n") >= 0);
	assert(index(stdout._buf, "Location: https://idp.com/auth\n") >= 0);
	assert(index(stdout._buf, "Set-Cookie: c=v\n") >= 0);
	assert(index(stdout._buf, "Content-Type: text/html\n") >= 0);
	assert(index(stdout._buf, "window.location.href=\"https://idp.com/auth\"") >= 0);
});

test('LOGIC: Web - Render Multiple Cookies', () => {
	let stdout = create_mock_stdout();
	let io = create_mock_io({}, stdout);
	
	let res = {
		status: 200,
		headers: {
			"Set-Cookie": ["c1=v1", "c2=v2"]
		},
		body: "OK"
	};
	
	web.render(io, res);
	
	assert(index(stdout._buf, "Set-Cookie: c1=v1\n") >= 0);
	assert(index(stdout._buf, "Set-Cookie: c2=v2\n") >= 0);
	assert(index(stdout._buf, "\n\nOK") >= 0);
});

test('LOGIC: Web - Render Error 500', () => {
	let stdout = create_mock_stdout();
	let io = create_mock_io({}, stdout);
	
	web.error(io, "Explosion!");
	
	assert(index(stdout._buf, "Status: 500 Internal Server Error\n") >= 0);
	assert(index(stdout._buf, "Content-Type: text/plain\n") >= 0);
	assert(index(stdout._buf, "Router Crash: Explosion!") >= 0);
});

test('LOGIC: Web - Handle Missing/Invalid Env', () => {
	let io = create_mock_io({}); // Empty env
	let req = web.request(io);
	assert_eq(req.path, "/");
	assert_eq(length(req.query), 0);
	assert_eq(length(req.cookies), 0);
});
