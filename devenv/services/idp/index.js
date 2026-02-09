const express = require('express');
const jose = require('jose');
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const APP_NAME = process.env.APP_NAME;
const ISSUER = process.env.ISSUER

let privateKey;
let publicKey;
let jwk;

const KEY_PATH = "secrets/signing_key.pem";

function log(message) {
  console.log(`[${APP_NAME}] ${message}`);
}

async function initKeys() {
    if (fs.existsSync(KEY_PATH)) {
        log(`Loading persistent signing key from ${KEY_PATH}`);
        const pem = fs.readFileSync(KEY_PATH, 'utf8');
        privateKey = await jose.importPKCS8(pem, 'RS256');
    } else {
        log(`Generating new signing key...`);
        const keys = await jose.generateKeyPair('RS256');
        privateKey = keys.privateKey;
        const pem = await jose.exportPKCS8(privateKey);
        fs.writeFileSync(KEY_PATH, pem, { mode: 0o600 });
        log(`Saved new signing key to ${KEY_PATH}`);
    }

    const pubKeyObject = crypto.createPublicKey(privateKey); 
    jwk = await jose.exportJWK(pubKeyObject);
    
    jwk.kid = 'mock-key-1';
    jwk.alg = 'RS256';
    jwk.use = 'sig';
}

app.get('/.well-known/openid-configuration', (req, res) => {
    res.json({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/auth`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        scopes_supported: ['openid', 'profile', 'email']
    });
});

app.get('/jwks', (req, res) => {
    res.json({ keys: [jwk] });
});

app.get('/auth', (req, res) => {
    const { client_id, redirect_uri, state, nonce, code_challenge, code_challenge_method } = req.query;
    log(`Auth request for ${client_id} (PKCE: ${code_challenge_method || 'none'})`);

    if (!code_challenge || code_challenge_method !== 'S256') {
        log(`REJECTED: PKCE S256 required, got method=${code_challenge_method}`);
        return res.status(400).send('PKCE S256 required');
    }

    const code = crypto.randomBytes(16).toString('hex');
    app.locals[code] = { 
        nonce, 
        client_id, 
        redirect_uri,
        code_challenge,
        expires_at: Date.now() + 300000 // 5-minute TTL
    };

    const callbackUrl = new URL(redirect_uri);
    callbackUrl.searchParams.set('code', code);
    callbackUrl.searchParams.set('state', state);

    log(`Redirecting back to ${callbackUrl.toString()}`);
    res.redirect(callbackUrl.toString());
});

app.post('/token', async (req, res) => {
    const { code, code_verifier } = req.body;
    log(`Token exchange for code: ${code}`);

    const context = app.locals[code];
    if (!context) return res.status(400).json({ error: 'invalid_code' });

    // Single-use enforcement and TTL check (Blocker #4 in 1770661270)
    delete app.locals[code];

    // PKCE Validation (Blocker #2 in 1770661250)
    if (!code_verifier) {
        log(`REJECTED: Missing code_verifier for ${context.client_id}`);
        return res.status(400).json({ error: 'invalid_grant', sub_error: 'missing_pkce_verifier' });
    }

    const calculatedChallenge = crypto.createHash('sha256')
        .update(code_verifier)
        .digest('base64url')
        .replace(/=/g, ''); // Ensure no padding as per RFC 7636

    if (calculatedChallenge !== context.code_challenge) {
        log(`REJECTED: PKCE mismatch for ${context.client_id}`);
        log(`  Expected (stored): ${context.code_challenge}`);
        log(`  Actual (calc):   ${calculatedChallenge}`);
        return res.status(400).json({ error: 'invalid_grant', sub_error: 'pkce_mismatch' });
    }

    if (Date.now() > context.expires_at) {
        log(`Authorization code expired for ${context.client_id}`);
        return res.status(400).json({ error: 'code_expired' });
    }

    const accessToken = 'mock-access-token';
    
    // Calculate at_hash: leftmost half of SHA-256 of access_token
    const fullHash = crypto.createHash('sha256').update(accessToken).digest();
    const halfHash = fullHash.slice(0, fullHash.length / 2);
    const atHash = jose.base64url.encode(halfHash);

    const idToken = await new jose.SignJWT({
        sub: '1234567890',
        name: 'John Doe',
        email: 'admin@example.com',
        email_verified: true,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        aud: context.client_id,
        iss: ISSUER,
        nonce: context.nonce,
        at_hash: atHash
    })
    .setProtectedHeader({ alg: 'RS256', kid: 'mock-key-1' })
    .sign(privateKey);

    res.json({
        access_token: accessToken,
        id_token: idToken,
        token_type: 'Bearer',
        expires_in: 3600
    });
});

// Load the shared certificates
const options = {
    key: fs.readFileSync("https.key"),
    cert: fs.readFileSync("https.crt")
};

initKeys().then(() => {
    https.createServer(options, app).listen(443, '0.0.0.0', () => {
        log(`Logical Issuer Identity: ${ISSUER}`);
    });
});
