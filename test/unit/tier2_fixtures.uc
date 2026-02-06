/**
 * Static Fixtures for Tier 2 (Business Logic)
 */

export const MOCK_CONFIG = {
    issuer_url: "https://trusted.idp",
    client_id: "luci-app",
    client_secret: "top-secret"
};

export const MOCK_DISCOVERY = {
    issuer: "https://trusted.idp",
    authorization_endpoint: "https://trusted.idp/auth",
    token_endpoint: "https://trusted.idp/token",
    jwks_uri: "https://trusted.idp/jwks"
};
