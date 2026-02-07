import { assert, assert_eq, when, and, then } from 'testing';
import * as router from 'luci_sso.router';
import * as crypto from 'luci_sso.crypto';
import * as session from 'luci_sso.session';
import * as f from 'integration.fixtures';

const TEST_SECRET = "integration-test-secret-32-bytes!!!";

function create_mock_io() {
	let io = {};
    io._responses = {};
    io._now = 1516239022 + 10;
    io._files = { "/etc/luci-sso/secret.key": TEST_SECRET };
    io._ubus_calls = [];
    
    io.time = function() { return io._now; };
    io.read_file = function(path) { return io._files[path]; };
    io.write_file = function(path, data) { io._files[path] = data; return true; };
    io.rename = function(old, newpath) {
        io._files[newpath] = io._files[old];
        delete io._files[old];
        return true;
    };
    io.remove = function(path) {
        delete io._files[path];
        return true;
    };
    io.mkdir = function(path, mode) {
        return true;
    };
    io.lsdir = function(path) {
        let results = [];
        let prefix = path;
        if (substr(prefix, -1) != "/") prefix += "/";
        for (let f in io._files) {
            if (index(f, prefix) == 0) {
                push(results, substr(f, length(prefix)));
            }
        }
        return results;
    };
    io.stat = function(path) {
        if (io._files[path] == null) return null;
        return { mtime: io._now };
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
        push(io._ubus_calls, { obj, method, args });
        if (obj == "session" && method == "login") {
            return { ubus_rpc_session: `session-for-${args.username}` };
        }
        return {};
    };
    
    return io;
}

const MOCK_CONFIG = {
	issuer_url: "https://idp.com",
    internal_issuer_url: "https://idp.com",
	client_id: "luci-app",
	client_secret: "secret123",
	redirect_uri: "http://router/callback",
	alg: "RS256",
	now: 1516239022 + 10,
	clock_tolerance: 300,
	user_mappings: [
		{ rpcd_user: "system_admin", rpcd_password: "p1", emails: ["1234567890"] }
	]
};

function mock_discovery(io, issuer) {
	io._responses[issuer + "/.well-known/openid-configuration"] = {
		status: 200,
		body: { 
			issuer: issuer, 
			authorization_endpoint: issuer + "/auth",
			token_endpoint: issuer + "/token",
			jwks_uri: issuer + "/jwks"
		}
	};
}

function mock_request(path, query, cookies) {
    return {
        path: path || "/",
        query: query || {},
        cookies: cookies || {}
    };
}

// =============================================================================
// Specifications (Tier 3 - System Documentation)
// =============================================================================

when("initiating the OIDC login flow", () => {
	let io = create_mock_io();
	
	and("the Identity Provider returns a massive response that exceeds memory limits", () => {
		io._responses["https://idp.com/.well-known/openid-configuration"] = { error: "RESPONSE_TOO_LARGE" };
		let res = router.handle(io, MOCK_CONFIG, mock_request("/"));
		then("it should fail discovery and return a 500 Internal Error", () => {
			assert_eq(res.status, 500);
		});
	});

		and("the Identity Provider is discoverable and healthy", () => {
			mock_discovery(io, "https://idp.com");
			let res = router.handle(io, MOCK_CONFIG, mock_request("/"));
			then("it should return a 302 redirect to the Identity Provider", () => {
				assert_eq(res.status, 302);
				assert(index(res.headers["Location"], "https://idp.com/auth") == 0);
			});
		});
	});
	
	when("processing the OIDC callback", () => {
		
		and("a valid user returns from the IdP with an honest token", () => {
			let io = create_mock_io();
			
			// Initiate handshake using real session logic
			let state_res = session.create_state(io);
			assert(state_res.ok);
			let handshake = state_res.data;
			let state_token = handshake.token;
	
			let id_token = f.sign_anchor_token(crypto, "https://idp.com", "1234567890", io.time(), handshake.nonce);
			
			mock_discovery(io, "https://idp.com");
			io._responses["https://idp.com/token"] = { status: 200, body: { access_token: "at", id_token: id_token } };
			io._responses["https://idp.com/jwks"] = { status: 200, body: { keys: [ f.ANCHOR_JWK ] } };
			
			let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: state_token });
			let res = router.handle(io, MOCK_CONFIG, req);
	
			then("it should verify all claims, create a LuCI session, and redirect to the dashboard", () => {
				assert_eq(res.status, 302);
				assert_eq(res.headers["Location"], "/cgi-bin/luci/");
				assert_eq(io._ubus_calls[0].method, "login");
				assert_eq(io._ubus_calls[0].args.username, "system_admin");
			});
		});
	
		and("the JWKS cache is stale (IdP rotated keys)", () => {
			let io = create_mock_io();
			let state_res = session.create_state(io);
			let handshake = state_res.data;
	
			mock_discovery(io, "https://idp.com");
	
			// 1. Populate cache with a WRONG key (but validly encoded)
			let cache_path = "/var/run/luci-sso/oidc-jwks-wv5enLcGYIn8PiwhdkeXzhVPct86Lf3q.json";
			io._files[cache_path] = sprintf("%J", {
				keys: [ { kid: "anchor-key", kty: "oct", k: "d3Jvbmc" } ],
				cached_at: io.time()
			});
	
			// 2. Prepare valid token and REAL JWKS on the network
			let id_token = f.sign_anchor_token(crypto, "https://idp.com", "1234567890", io.time(), handshake.nonce);
			io._responses["https://idp.com/token"] = { status: 200, body: { access_token: "at", id_token: id_token } };
			io._responses["https://idp.com/jwks"] = { status: 200, body: { keys: [ f.ANCHOR_JWK ] } };
	
			let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: handshake.token });
			let res = router.handle(io, MOCK_CONFIG, req);
	
			then("it should detect the failure, force a refresh, and eventually succeed", () => {
				assert_eq(res.status, 302, "Should recover and redirect");
				assert_eq(res.headers["Location"], "/cgi-bin/luci/");
				
				// Verify that the cache was UPDATED on disk
				let cache_content = json(io._files[cache_path]);
				assert(cache_content, "Cache file should exist");
				assert_eq(cache_content.keys[0].kid, f.ANCHOR_JWK.kid, "Cache should now contain the correct key ID");
			});
		});
    and("the user is authenticated at the IdP but NOT found in our local whitelist", () => {
        let io = create_mock_io();
		
		let state_res = session.create_state(io);
		assert(state_res.ok);
		let handshake = state_res.data;

		let id_token = f.sign_anchor_token(crypto, "https://idp.com", "unknown-user", io.time(), handshake.nonce);

		mock_discovery(io, "https://idp.com");
		io._responses["https://idp.com/token"] = { status: 200, body: { access_token: "at", id_token: id_token } };
		io._responses["https://idp.com/jwks"] = { status: 200, body: { keys: [ f.ANCHOR_JWK ] } };
		
		let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: handshake.token });
        
        // Use config with NO mappings
		let bad_config = { ...MOCK_CONFIG, user_mappings: [] };
		let res = router.handle(io, bad_config, req);

        then("it should return a 403 Forbidden explaining the unauthorized access", () => {
            assert_eq(res.status, 403);
        });
    });

    and("an attacker attempts a CSRF attack by forging the state parameter", () => {
        let io = create_mock_io();
		let state_res = session.create_state(io);
		let handshake = state_res.data;

		let req = mock_request("/callback", { code: "c", state: "evil-state" }, { luci_sso_state: handshake.token });
		let res = router.handle(io, MOCK_CONFIG, req);

        then("it should detect the state mismatch and return a 403 Forbidden", () => {
            assert_eq(res.status, 403);
        });
    });

	and("the Identity Provider returns an explicit error (e.g. user cancelled)", () => {
		let io = create_mock_io();
		let req = mock_request("/callback", { error: "access_denied", error_description: "User cancelled" });
		let res = router.handle(io, MOCK_CONFIG, req);

		then("it should show the error to the user and return a 400 Bad Request", () => {
			assert_eq(res.status, 400);
		});
	});

    and("the network connection to the Identity Provider fails during backchannel exchange", () => {
        let io = create_mock_io();
		let state_res = session.create_state(io);
		let handshake = state_res.data;

		mock_discovery(io, "https://idp.com");
		io._responses["https://idp.com/token"] = { error: "CONNECT_TIMEOUT" };
		
		let req = mock_request("/callback", { code: "c", state: handshake.state }, { luci_sso_state: handshake.token });
		let res = router.handle(io, MOCK_CONFIG, req);

        then("it should fail safely with a 500 Internal Error", () => {
            assert_eq(res.status, 500);
        });
    });
});

when("a user requests to logout", () => {
	let io = create_mock_io();
	let res = router.handle(io, MOCK_CONFIG, mock_request("/logout", {}, { sysauth: "session-12345" }));

	then("it should destroy the UBUS session on the server side", () => {
		let call = null;
		for (let c in io._ubus_calls) {
			if (c.obj == "session" && c.method == "destroy") call = c;
		}
		assert(call, "ubus session:destroy should have been called");
		assert_eq(call.args.ubus_rpc_session, "session-12345");
	});

	then("it should clear the LuCI session cookies", () => {
		assert(type(res.headers["Set-Cookie"]) == "array", "Set-Cookie should be an array for logout");
		let cleared_sysauth = false;
		for (let cookie in res.headers["Set-Cookie"]) {
			if (index(cookie, "sysauth=") == 0 && index(cookie, "Max-Age=0") > 0) cleared_sysauth = true;
		}
		assert(cleared_sysauth, "Should have cleared sysauth cookie");
	});

	then("it should redirect back to the root page", () => {
		assert_eq(res.headers["Location"], "/");
	});
});

when("accessing an unhandled system path", () => {
	let io = create_mock_io();
	let res = router.handle(io, MOCK_CONFIG, mock_request("/unknown/path"));

	then("it should return a 404 Not Found error", () => {
		assert_eq(res.status, 404);
	});
});
