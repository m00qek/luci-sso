import * as mbedtls from 'crypto_mbedtls';

/**
 * Converts Base64URL to Standard Base64 and adds padding.
 */
function b64url_to_b64(str) {
    if (type(str) != "string") return null;
    if (length(str) == 0) return "";
    
    // 1. Map characters
    let b64 = replace(str, /-/g, '+');
    b64 = replace(b64, /_/g, '/');
    
    // 2. Add padding
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
 * Parses and validates a JWT (RS256 or ES256).
 */
export function verify_jwt(token, pubkey) {
    if (type(token) != "string") return null;

    let parts = split(token, ".");
    if (length(parts) != 3) return null;

    // 1. Decode Header
    let header_b64 = b64url_to_b64(parts[0]);
    let header_json = b64dec(header_b64);
    if (!header_json) return null;
    
    let header = safe_json(header_json);
    if (!header || !header.alg) return null;

    // 2. Decode Signature
    let sig_b64 = b64url_to_b64(parts[2]);
    let signature = b64dec(sig_b64);
    if (!signature) return null;

    // 3. Verify Signature
    let signed_data = parts[0] + "." + parts[1];
    let valid = false;

    if (header.alg == "RS256") {
        valid = mbedtls.verify_rs256(signed_data, signature, pubkey);
    } else if (header.alg == "ES256") {
        valid = mbedtls.verify_es256(signed_data, signature, pubkey);
    } else {
        return null; // Unsupported algorithm
    }

    if (!valid) return null;

    // 4. Decode Payload
    let payload_b64 = b64url_to_b64(parts[1]);
    let payload_json = b64dec(payload_b64);
    if (!payload_json) return null;

    let payload = safe_json(payload_json);
    if (!payload) return null;

    // 5. Basic OIDC Claims Validation
    let now = time();
    if (payload.exp && payload.exp < now) return null;
    if (payload.nbf && payload.nbf > now) return null;

    return payload;
};

/**
 * Decodes a Base64URL string to a raw string.
 */
export function b64url_decode(str) {
    let b64 = b64url_to_b64(str);
    return (b64 != null) ? b64dec(b64) : null;
};