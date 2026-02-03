import * as mbedtls from 'crypto_mbedtls';

/**
 * Converts Base64URL to Standard Base64 and adds padding.
 */
function b64url_to_b64(str) {
    if (type(str) != "string") return null;
    if (length(str) == 0) return "";
    
    // Validate Base64URL charset: [A-Za-z0-9_-]
    if (!match(str, /^[A-Za-z0-9_-]+$/)) return null;
    
    let b64 = replace(str, /-/g, '+');
    b64 = replace(b64, /_/g, '/');
    
    let pad = (4 - (length(b64) % 4)) % 4;
    for (let i = 0; i < pad; i++) {
        b64 += '=';
    }
    
    return b64;
}

function safe_json(str) {
    try {
        return json(str);
    } catch (e) {
        return null;
    }
}

/**
 * Decodes a Base64URL string to a raw string.
 */
export function b64url_decode(str) {
    let b64 = b64url_to_b64(str);
    return (b64 != null) ? b64dec(b64) : null;
};

/**
 * Encodes a raw string to Base64URL.
 */
export function b64url_encode(str) {
    let b64 = b64enc(str);
    b64 = replace(b64, /\+/g, '-');
    b64 = replace(b64, /\//g, '_');
    b64 = replace(b64, /=/g, '');
    return b64;
};

/**
 * Parses and validates a JWT.
 */
export function verify_jwt(token, pubkey, options) {
    if (type(token) != "string") return { error: "TOKEN_NOT_STRING" };
    if (!options || !options.alg) return { error: "MISSING_ALGORITHM_OPTION" };

    let parts = split(token, ".");
    if (length(parts) != 3) return { error: "MALFORMED_JWT" };

    // 1. Decode Header
    let header_b64 = b64url_to_b64(parts[0]);
    let header_json = b64dec(header_b64);
    if (!header_json) return { error: "INVALID_HEADER_ENCODING" };
    
    let header = safe_json(header_json);
    if (!header || !header.alg) return { error: "INVALID_HEADER_JSON" };

    // 2. Algorithm Enforcement
    if (header.alg != options.alg) {
        return { error: "ALGORITHM_MISMATCH", details: `Expected ${options.alg}, got ${header.alg}` };
    }

    // 3. Decode Signature
    let sig_b64 = b64url_to_b64(parts[2]);
    let signature = b64dec(sig_b64);
    if (!signature) return { error: "INVALID_SIGNATURE_ENCODING" };

    // 4. Verify Signature
    let signed_data = parts[0] + "." + parts[1];
    let valid = false;

    if (options.alg == "RS256") {
        valid = mbedtls.verify_rs256(signed_data, signature, pubkey);
    } else if (options.alg == "ES256") {
        valid = mbedtls.verify_es256(signed_data, signature, pubkey);
    } else {
        return { error: "UNSUPPORTED_ALGORITHM" };
    }

    if (!valid) return { error: "INVALID_SIGNATURE" };

    // 5. Decode Payload
    let payload_b64 = b64url_to_b64(parts[1]);
    let payload_json = b64dec(payload_b64);
    if (!payload_json) return { error: "INVALID_PAYLOAD_ENCODING" };

    let payload = safe_json(payload_json);
    if (!payload) return { error: "INVALID_PAYLOAD_JSON" };

    // 6. Claims Validation
    let skew = options.skew || 300; // Default 5 minutes
    let now = time();

    if (payload.exp && payload.exp < (now - skew)) {
        return { error: "TOKEN_EXPIRED" };
    }
    
    if (payload.nbf && payload.nbf > (now + skew)) {
        return { error: "TOKEN_NOT_YET_VALID" };
    }

    if (options.iss && payload.iss != options.iss) {
        return { error: "ISSUER_MISMATCH" };
    }

    if (options.aud && payload.aud != options.aud) {
        return { error: "AUDIENCE_MISMATCH" };
    }

    return { payload: payload };
};

/**
 * Calculates SHA-256 hash (raw binary).
 */
export function sha256(input) {
    return mbedtls.sha256(input);
};

/**
 * Generates cryptographically secure random bytes.
 */
export function random(len) {
    return mbedtls.random(len);
};

/**
 * Generates a PKCE Code Verifier.
 * 
 * @param {int} len - Number of random bytes (default 43, results in 57 chars).
 * @returns {string} - Base64URL encoded verifier.
 */
export function pkce_generate_verifier(len) {
    let bytes = mbedtls.random(len || 43);
    return b64url_encode(bytes);
};

/**
 * Calculates a PKCE Code Challenge from a verifier using S256.
 * 
 * @param {string} verifier - The verifier string.
 * @returns {string} - Base64URL encoded SHA-256 hash.
 */
export function pkce_calculate_challenge(verifier) {
    let hash = mbedtls.sha256(verifier);
    return b64url_encode(hash);
};

/**
 * Generates a PKCE Verifier and Challenge pair.
 */
export function pkce_pair(len) {
    let verifier = pkce_generate_verifier(len);
    let challenge = pkce_calculate_challenge(verifier);
    return { verifier, challenge };
};
