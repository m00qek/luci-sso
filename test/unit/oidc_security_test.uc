import { test, assert, assert_eq } from 'testing';
import * as oidc from 'luci_sso.oidc';
import * as mock from 'mock';
import * as f from 'unit.tier2_fixtures';

test('OIDC: Security - Reject insecure token endpoint', () => {
	let insecure_disc = { ...f.MOCK_DISCOVERY, token_endpoint: "http://insecure.com/token" };
	mock.create().with_responses({}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, insecure_disc, "code", "verifier-is-long-enough-to-pass-basic-check-123");
		assert(!res.ok);
		assert_eq(res.error, "INSECURE_TOKEN_ENDPOINT");
	});
});

test('OIDC: Security - Handle network failure during exchange', () => {
	mock.create().with_responses({
		[f.MOCK_DISCOVERY.token_endpoint]: { error: "TLS_VERIFY_FAILED" }
	}, (io) => {
		let res = oidc.exchange_code(io, f.MOCK_CONFIG, f.MOCK_DISCOVERY, "code", "verifier-is-long-enough-to-pass-basic-check-123");
		assert(!res.ok);
		assert_eq(res.error, "NETWORK_ERROR");
	});
});

test('OIDC: Security - Reject insecure issuer URL', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.discover(io, "http://insecure.idp");
		assert(!res.ok);
		assert_eq(res.error, "INSECURE_ISSUER_URL");
	});
});

test('OIDC: Security - Reject insecure internal issuer URL', () => {
	mock.create().with_responses({}, (io) => {
		let res = oidc.discover(io, "https://secure.idp", { internal_issuer_url: "http://insecure.local" });
		assert(!res.ok);
		assert_eq(res.error, "INSECURE_FETCH_URL");
	});
});

test('OIDC: Security - Reject discovery document with insecure endpoints', () => {
	let evil_disc = { 
		...f.MOCK_DISCOVERY, 
		jwks_uri: "http://insecure.idp/jwks" 
	};
	let issuer = "https://trusted.idp";
	let url = issuer + "/.well-known/openid-configuration";

	mock.create().with_responses({ [url]: { status: 200, body: evil_disc } }, (io) => {
		let res = oidc.discover(io, issuer);
		assert(!res.ok);
		assert_eq(res.error, "INSECURE_ENDPOINT");
	});
});
