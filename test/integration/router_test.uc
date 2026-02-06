import { assert, assert_eq, when, and, then } from 'testing';
import * as router from 'luci_sso.router';
import * as crypto from 'luci_sso.crypto';
import * as f from 'unit.tier1_fixtures';

const TEST_SECRET = "integration-test-secret-32-bytes!!!";

function create_mock_io() {
	let io = {};
    io._responses = {};
    io._now = 1516239022 + 10;
    io._files = { "/etc/luci-sso/secret.key": TEST_SECRET };
    io._ubus_logins = [];
    
    io.time = function() { return io._now; };
    io.read_file = function(path) { return io._files[path]; };
    io.write_file = function(path, data) { io._files[path] = data; return true; };
    io.rename = function(old, newpath) {
        io._files[newpath] = io._files[old];
        delete io._files[old];
        return true;
    };
    
    io.http_get = function(url) { 
        let res = io._responses[url] || { status: 404, body: "" };
        let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
        return { status: res.status, body: { read: () => raw_body } };
    };
    
    io.http_post = function(url, opts) {
        let res = io._responses[url] || { status: 404, body: "" };
        let raw_body = (type(res.body) == "string") ? res.body : sprintf("%J", res.body);
        return { status: res.status, body: { read: () => raw_body } };
    };
    
    io.log = function() { };
    
    io.ubus_call = function(obj, method, args) {
        if (obj == "session" && method == "login") {
            push(io._ubus_logins, args);
            return { ubus_rpc_session: `session-for-${args.username}` };
        }
        return {};
    };
    
    return io;
}

const MOCK_CONFIG = {
	issuer_url: null,
    internal_issuer_url: "https://idp.com",
	client_id: null,
	client_secret: "secret123",
	redirect_uri: "http://router/callback",
	alg: "RS256",
	now: 1516239022 + 10,
	user_mappings: [
		{ rpcd_user: "system_admin", rpcd_password: "p1", emails: ["1234567890"] }
	]
};

const RS256_JWK = {
	kty: "RSA",
	n: "q0g5x3uxj4F9zmlMbadqN8rJpdebwZL2iMNFmaBCBLRX3neuHobGuMh16Wgt5NiW8-rD_2du7uA76nmUzoUBt3nF5LMtngFGJXFRpy6srKne5Ch9g4RZZrQA5VvE_Rviv3XQ7YbXZe55pRcvNjcxwSIKTGfAw4p1jUu1ty4sg0jVJsPAnp6EOIq7euWpqIRkyxT94VR_QQO9mLcjjuO7ta_ahC8pbGOOIOk7AtCd_KV56tk1Tid5iaYV8RIhXSDeef9q7-L9DY6pK1Mx2Yu8SdPkhgj5kswoqnQWwViDUZAw59eos6Hrbhdh4aFg9mUQm-qCNLXxScFg-X7xcW91pQ",
	e: "AQAB"
};

function mock_discovery(io, issuer) {
	io._responses[issuer + "/.well-known/openid-configuration"] = {
		status: 200,
		body: { 
			issuer: null, 
			authorization_endpoint: issuer + "/auth",
			token_endpoint: issuer + "/token",
			jwks_uri: issuer + "/jwks"
		}
	};
}

// =============================================================================
// Specifications (Tier 3 - System Documentation)
// =============================================================================

when("initiating the OIDC login flow", () => {
	let io = create_mock_io();
	
	and("the Identity Provider returns a massive response that exceeds memory limits", () => {
		io._responses["https://idp.com/.well-known/openid-configuration"] = { error: "RESPONSE_TOO_LARGE" };
		let res = router.handle(io, MOCK_CONFIG, { path: "/" });
		then("it should fail discovery and return a 500 Internal Error", () => {
			assert_eq(res.status, 500);
		});
	});

	and("the Identity Provider is discoverable and healthy", () => {
		mock_discovery(io, "https://idp.com");
		let res = router.handle(io, MOCK_CONFIG, { path: "/" });
		then("it should return a 302 redirect to the Identity Provider", () => {
			assert_eq(res.status, 302);
			assert(index(res.headers[0], "Location: https://idp.com/auth") == 0);
		});
	});
});

when("processing the OIDC callback", () => {
	
	and("a valid user returns from the IdP with an honest token", () => {
		let io = create_mock_io();
		let state = crypto.b64url_encode(crypto.random(16));
		let payload = { state: state, code_verifier: "v", nonce: null, issuer_url: "https://idp.com", iat: io.time(), exp: io.time() + 300 };
		let state_token = crypto.sign_jws(payload, TEST_SECRET);

		mock_discovery(io, "https://idp.com");
		io._responses["https://idp.com/token"] = { status: 200, body: { access_token: "at", id_token: f.PLUMBING_RSA.token } };
		io._responses["https://idp.com/jwks"] = { status: 200, body: { keys: [ RS256_JWK ] } };
		
		let req = { path: "/callback", query_string: `code=c&state=${state}`, http_cookie: `luci_sso_state=${state_token}` };
		let res = router.handle(io, MOCK_CONFIG, req);

		then("it should verify all claims, create a LuCI session, and redirect to the dashboard", () => {
			assert_eq(res.status, 302);
			assert_eq(res.headers[0], "Location: /cgi-bin/luci/");
			assert_eq(io._ubus_logins[0].username, "system_admin");
		});
	});

    and("the user is authenticated at the IdP but NOT found in our local whitelist", () => {
        let io = create_mock_io();
		let state = crypto.b64url_encode(crypto.random(16));
		let payload = { state: state, code_verifier: "v", nonce: null, issuer_url: "https://idp.com", iat: io.time(), exp: io.time() + 300 };
		let state_token = crypto.sign_jws(payload, TEST_SECRET);

		mock_discovery(io, "https://idp.com");
		io._responses["https://idp.com/token"] = { status: 200, body: { access_token: "at", id_token: f.PLUMBING_RSA.token } };
		io._responses["https://idp.com/jwks"] = { status: 200, body: { keys: [ RS256_JWK ] } };
		
		let req = { path: "/callback", query_string: `code=c&state=${state}`, http_cookie: `luci_sso_state=${state_token}` };
        
        // Use config with NO mappings
		let bad_config = { ...MOCK_CONFIG, user_mappings: [] };
		let res = router.handle(io, bad_config, req);

        then("it should return a 403 Forbidden explaining the unauthorized access", () => {
            assert_eq(res.status, 403);
        });
    });

    and("an attacker attempts a CSRF attack by forging the state parameter", () => {
        let io = create_mock_io();
		let state = "honest-state";
		let payload = { state: state, code_verifier: "v", nonce: null, issuer_url: "https://idp.com", iat: io.time(), exp: io.time() + 300 };
		let state_token = crypto.sign_jws(payload, TEST_SECRET);

		let req = { path: "/callback", query_string: "code=c&state=evil-state", http_cookie: `luci_sso_state=${state_token}` };
		let res = router.handle(io, MOCK_CONFIG, req);

        then("it should detect the state mismatch and return a 403 Forbidden", () => {
            assert_eq(res.status, 403);
        });
    });

	and("the Identity Provider returns an explicit error (e.g. user cancelled)", () => {
		let io = create_mock_io();
		let req = {
			path: "/callback",
			query_string: "error=access_denied&error_description=User+cancelled"
		};
		let res = router.handle(io, MOCK_CONFIG, req);

		then("it should show the error to the user and return a 400 Bad Request", () => {
			assert_eq(res.status, 400);
		});
	});

    and("the network connection to the Identity Provider fails during backchannel exchange", () => {
        let io = create_mock_io();
		let state = crypto.b64url_encode(crypto.random(16));
		let payload = { state: state, code_verifier: "v", nonce: null, issuer_url: "https://idp.com", iat: io.time(), exp: io.time() + 300 };
		let state_token = crypto.sign_jws(payload, TEST_SECRET);

		mock_discovery(io, "https://idp.com");
		io._responses["https://idp.com/token"] = { error: "CONNECT_TIMEOUT" };
		
		let req = { path: "/callback", query_string: `code=c&state=${state}`, http_cookie: `luci_sso_state=${state_token}` };
		let res = router.handle(io, MOCK_CONFIG, req);

        then("it should fail safely with a 500 Internal Error", () => {
            assert_eq(res.status, 500);
        });
    });
});

when("a user requests to logout", () => {
	let io = create_mock_io();
	let res = router.handle(io, MOCK_CONFIG, { path: "/logout" });

	then("it should clear the LuCI session cookies", () => {
		assert(index(res.headers[1], "sysauth_https=;") >= 0);
		assert(index(res.headers[2], "sysauth=;") >= 0);
	});

	then("it should redirect back to the root page", () => {
		assert_eq(res.headers[0], "Location: /");
	});
});

when("accessing an unhandled system path", () => {
	let io = create_mock_io();
	let res = router.handle(io, MOCK_CONFIG, { path: "/unknown/path" });

	then("it should return a 404 Not Found error", () => {
		assert_eq(res.status, 404);
	});
});
