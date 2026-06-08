'use strict';

/**
 * Public error codes for luci-sso.
 *
 * Every constant exported here must be documented in docs/reference/log-messages.md,
 * and every code in that document must be exported here.
 * CI enforces this bidirectional constraint via devenv/scripts/check-error-codes.sh.
 *
 * Internal codes used only inside a single subsystem do not belong here.
 */

// Configuration
export const SSO_DISABLED              = "SSO_DISABLED";
export const CONFIG_ERROR              = "CONFIG_ERROR";
export const UCI_ERROR                 = "UCI_ERROR";

// Discovery
export const INSECURE_ISSUER_URL       = "INSECURE_ISSUER_URL";
export const INSECURE_FETCH_URL        = "INSECURE_FETCH_URL";
export const OIDC_DISCOVERY_FAILED     = "OIDC_DISCOVERY_FAILED";
export const DISCOVERY_FAILED          = "DISCOVERY_FAILED";
export const DISCOVERY_NETWORK_ERROR   = "DISCOVERY_NETWORK_ERROR";
export const INVALID_DISCOVERY_DOC     = "INVALID_DISCOVERY_DOC";
export const DISCOVERY_MISSING_ISSUER  = "DISCOVERY_MISSING_ISSUER";
export const DISCOVERY_ISSUER_MISMATCH = "DISCOVERY_ISSUER_MISMATCH";
export const DISCOVERY_MISSING_ENDPOINT = "DISCOVERY_MISSING_ENDPOINT";
export const INSECURE_ENDPOINT         = "INSECURE_ENDPOINT";
export const JWKS_FETCH_FAILED         = "JWKS_FETCH_FAILED";
export const JWKS_NETWORK_ERROR        = "JWKS_NETWORK_ERROR";
export const INSECURE_JWKS_URI         = "INSECURE_JWKS_URI";
export const INVALID_JWKS_FORMAT       = "INVALID_JWKS_FORMAT";

// Handshake initiation
export const INSECURE_AUTH_ENDPOINT    = "INSECURE_AUTH_ENDPOINT";
export const INVALID_AUTH_ENDPOINT     = "INVALID_AUTH_ENDPOINT";
export const MISSING_STATE_PARAMETER   = "MISSING_STATE_PARAMETER";
export const MISSING_NONCE_PARAMETER   = "MISSING_NONCE_PARAMETER";
export const MISSING_PKCE_CHALLENGE    = "MISSING_PKCE_CHALLENGE";

// Callback
export const IDP_ERROR                 = "IDP_ERROR";
export const MISSING_CODE              = "MISSING_CODE";
export const MISSING_HANDSHAKE_COOKIE  = "MISSING_HANDSHAKE_COOKIE";
export const STATE_PARAMETER_MISMATCH  = "STATE_PARAMETER_MISMATCH";
export const STATE_NOT_FOUND           = "STATE_NOT_FOUND";
export const STATE_CORRUPTED           = "STATE_CORRUPTED";
export const STATE_SAVE_FAILED         = "STATE_SAVE_FAILED";
export const MALFORMED_STATE_COOKIE    = "MALFORMED_STATE_COOKIE";
export const HANDSHAKE_EXPIRED            = "HANDSHAKE_EXPIRED";
export const HANDSHAKE_NOT_YET_VALID      = "HANDSHAKE_NOT_YET_VALID";
export const HANDSHAKE_CAPACITY_EXCEEDED  = "HANDSHAKE_CAPACITY_EXCEEDED";

// Token exchange
export const INSECURE_TOKEN_ENDPOINT        = "INSECURE_TOKEN_ENDPOINT";
export const INVALID_PKCE_VERIFIER          = "INVALID_PKCE_VERIFIER";
export const TOKEN_ENDPOINT_NETWORK_ERROR   = "TOKEN_ENDPOINT_NETWORK_ERROR";
export const OIDC_INVALID_GRANT             = "OIDC_INVALID_GRANT";
export const TOKEN_EXCHANGE_FAILED          = "TOKEN_EXCHANGE_FAILED";
export const TOKEN_RESPONSE_INVALID_JSON    = "TOKEN_RESPONSE_INVALID_JSON";

// Token validation
export const UNSUPPORTED_ALGORITHM     = "UNSUPPORTED_ALGORITHM";
export const INVALID_SIGNATURE         = "INVALID_SIGNATURE";
export const ID_TOKEN_VERIFICATION_FAILED = "ID_TOKEN_VERIFICATION_FAILED";
export const MISSING_ID_TOKEN          = "MISSING_ID_TOKEN";
export const MISSING_SUB_CLAIM         = "MISSING_SUB_CLAIM";
export const MISSING_EXP_CLAIM         = "MISSING_EXP_CLAIM";
export const MISSING_IAT_CLAIM         = "MISSING_IAT_CLAIM";
export const MISSING_NONCE             = "MISSING_NONCE";
export const NONCE_MISMATCH            = "NONCE_MISMATCH";
export const MISSING_AZP_CLAIM         = "MISSING_AZP_CLAIM";
export const AZP_MISMATCH              = "AZP_MISMATCH";
export const MISSING_ACCESS_TOKEN      = "MISSING_ACCESS_TOKEN";
export const MISSING_AT_HASH           = "MISSING_AT_HASH";
export const AT_HASH_MISMATCH          = "AT_HASH_MISMATCH";

// UserInfo
export const INSECURE_USERINFO_ENDPOINT = "INSECURE_USERINFO_ENDPOINT";
export const USERINFO_FETCH_FAILED      = "USERINFO_FETCH_FAILED";
export const USERINFO_NETWORK_ERROR     = "USERINFO_NETWORK_ERROR";
export const USERINFO_INVALID_JSON      = "USERINFO_INVALID_JSON";
export const IDENTITY_MISMATCH          = "IDENTITY_MISMATCH";

// Authorization
export const USER_NOT_AUTHORIZED          = "USER_NOT_AUTHORIZED";
export const TOKEN_REPLAYED               = "TOKEN_REPLAYED";
export const TOKEN_REGISTRY_ERROR         = "TOKEN_REGISTRY_ERROR";
export const CSRF_CHECK_FAILED            = "CSRF_CHECK_FAILED";

// Session (UBUS)
export const UBUS_LOGIN_FAILED         = "UBUS_LOGIN_FAILED";
export const UBUS_CONNECT_FAILED       = "UBUS_CONNECT_FAILED";
export const UBUS_ERROR                = "UBUS_ERROR";
export const UBUS_SESSION_FAILED       = "UBUS_SESSION_FAILED";

// Routing
export const NOT_FOUND                 = "NOT_FOUND";
export const TOO_MANY_REQUESTS         = "TOO_MANY_REQUESTS";
export const INPUT_TOO_LARGE           = "INPUT_TOO_LARGE";

// System
export const SYSTEM_INIT_FAILED        = "SYSTEM_INIT_FAILED";
export const SSL_INIT_FAILED           = "SSL_INIT_FAILED";
export const CRYPTO_ERROR              = "CRYPTO_ERROR";
export const CRYPTO_INIT_FAILED        = "CRYPTO_INIT_FAILED";
