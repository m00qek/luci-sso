const express = require('express');
const jose = require('jose');
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = 5556;
const ISSUER = process.env.PUBLIC_ISSUER || `https://localhost:${PORT}`;

let privateKey;
let publicKey;
let jwk;

async function initKeys() {
    const keys = await jose.generateKeyPair('RS256');
    privateKey = keys.privateKey;
    publicKey = keys.publicKey;
    jwk = await jose.exportJWK(publicKey);
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
    const { client_id, redirect_uri, state, nonce } = req.query;
    console.log(`[MockIdP] Auth request for ${client_id}`);

    const code = crypto.randomBytes(16).toString('hex');
    app.locals[code] = { nonce, client_id, redirect_uri };

    const callbackUrl = new URL(redirect_uri);
    callbackUrl.searchParams.set('code', code);
    callbackUrl.searchParams.set('state', state);

    console.log(`[MockIdP] Redirecting back to ${callbackUrl.toString()}`);
    res.redirect(callbackUrl.toString());
});

app.post('/token', async (req, res) => {
    const { code } = req.body;
    console.log(`[MockIdP] Token exchange for code: ${code}`);

    const context = app.locals[code];
    if (!context) return res.status(400).json({ error: 'invalid_code' });

    const idToken = await new jose.SignJWT({
        sub: '1234567890',
        name: 'John Doe',
        email: 'admin@example.com',
        email_verified: true,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        aud: context.client_id,
        iss: ISSUER,
        nonce: context.nonce
    })
    .setProtectedHeader({ alg: 'RS256', kid: 'mock-key-1' })
    .sign(privateKey);

    res.json({
        access_token: 'mock-access-token',
        id_token: idToken,
        token_type: 'Bearer',
        expires_in: 3600
    });
});

// Load the shared certificates
const options = {
    key: fs.readFileSync('/etc/luci-sso/certs/idp.key'),
    cert: fs.readFileSync('/etc/luci-sso/certs/idp.crt')
};

initKeys().then(() => {
    https.createServer(options, app).listen(PORT, '0.0.0.0', () => {
        console.log(`[MockIdP] OIDC Provider (HTTPS) running on port ${PORT}`);
        console.log(`[MockIdP] Logical Issuer Identity: ${ISSUER}`);
    });
});
