import { assert, assert_eq, when, then } from 'testing';
import * as oidc from 'luci_sso.oidc';
import * as mock from 'mock';

const MOCK_CONFIG = {
	client_id: "client123",
	client_secret: "secret123",
	redirect_uri: "https://app.com/callback",
	issuer_url: "https://idp.com"
};

const MOCK_DISCOVERY = {
	issuer: "https://idp.com",
	token_endpoint: "http://idp.com/token", // INSECURE
	authorization_endpoint: "https://idp.com/auth",
	jwks_uri: "https://idp.com/jwks"
};

when("exchanging code with an insecure token endpoint", () => {
	mock.create().with_files({}, (io) => {
		then("it should reject the exchange with INSECURE_TOKEN_ENDPOINT", () => {
			let res = oidc.exchange_code(io, MOCK_CONFIG, MOCK_DISCOVERY, "code123", "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long");
			assert_eq(res.ok, false);
			assert_eq(res.error, "INSECURE_TOKEN_ENDPOINT");
		});
	});
});

when("exchanging code and the network fails (e.g. invalid certificate)", () => {
	mock.create().with_responses({ "https://idp.com/token": { error: "CERT_VALIDATION_FAILED" } }, (io) => {
		then("it should return NETWORK_ERROR", () => {
			let secure_discovery = { ...MOCK_DISCOVERY, token_endpoint: "https://idp.com/token" };
			let res = oidc.exchange_code(io, MOCK_CONFIG, secure_discovery, "code123", "a-very-long-and-secure-verifier-that-is-at-least-43-chars-long");
			assert_eq(res.ok, false);
			assert_eq(res.error, "NETWORK_ERROR");
		});
	});
});

when("discovering an IdP with an insecure issuer URL", () => {
	mock.create().with_files({}, (io) => {
		then("it should reject discovery with INSECURE_ISSUER_URL", () => {
			let res = oidc.discover(io, "http://insecure-idp.com");
			assert_eq(res.ok, false);
			assert_eq(res.error, "INSECURE_ISSUER_URL");
		});
	});
});

when("discovering an IdP with an insecure internal issuer URL", () => {
	mock.create().with_files({}, (io) => {
		then("it should reject discovery with INSECURE_FETCH_URL", () => {
			let res = oidc.discover(io, "https://idp.com", { internal_issuer_url: "http://internal-idp.com" });
			assert_eq(res.ok, false);
			assert_eq(res.error, "INSECURE_FETCH_URL");
		});
	});
});

when("discovering an IdP where discovery document contains insecure endpoints", () => {
	let discovery_body = {
		issuer: "https://idp.com",
		authorization_endpoint: "https://idp.com/auth",
		token_endpoint: "http://idp.com/token", // INSECURE
		jwks_uri: "https://idp.com/jwks"
	};
	
	mock.create().with_responses({ "https://idp.com/.well-known/openid-configuration": { status: 200, body: discovery_body } }, (io) => {
		then("it should reject the discovery with INSECURE_ENDPOINT", () => {
			let res = oidc.discover(io, "https://idp.com");
			assert_eq(res.ok, false);
			assert_eq(res.error, "INSECURE_ENDPOINT");
			assert_eq(res.details, "token_endpoint");
		});
	});
});