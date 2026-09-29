'use strict';

// The Authelia consent page of docs/how-to/providers/authelia.md. Run by
// authelia.sh; see common.js for the capture rules.
//
// The browser opens the authorization request luci-sso sends (oidc.uc
// get_auth_url: code flow, S256 PKCE, state and nonce), signs in as the test
// user and stops at the consent page. Nothing reaches the router: requests
// to router.example.com are answered in the browser.
//
//   authelia-consent.png   the consent page: client name, requested scopes,
//                          Remember Consent, Accept and Deny

const crypto = require('crypto');
const { launch, settle, shot, run } = require('./common');

const AUTHELIA = `https://${process.env.HOST}`;
const REDIRECT_URI = 'https://router.example.com/cgi-bin/luci-sso/callback';

function b64url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

run(async () => {
  const discovery = await (await fetch(`${AUTHELIA}/.well-known/openid-configuration`)).json();
  const verifier = b64url(crypto.randomBytes(43));
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: 'luci-router',
    redirect_uri: REDIRECT_URI,
    scope: 'openid profile email groups',
    state: b64url(crypto.randomBytes(32)),
    nonce: b64url(crypto.randomBytes(32)),
    code_challenge: b64url(crypto.createHash('sha256').update(verifier).digest()),
    code_challenge_method: 'S256',
  });

  const { browser, context, page } = await launch();
  await context.route('https://router.example.com/**', (route) => route.fulfill({ status: 200, body: 'router' }));

  await page.goto(`${discovery.authorization_endpoint}?${params}`);
  await settle(page, 1500);
  await page.fill('#username-textfield', 'alice');
  await page.fill('#password-textfield', process.env.USER_PASSWORD);
  await page.click('#sign-in-button');
  await page.waitForSelector('#openid-consent-accept');
  await settle(page, 1000);

  const card = page.locator('#openid-consent-accept').locator('xpath=ancestor::div[contains(@class,"max-w-xl")][1]');
  await shot(page, 'authelia-consent', [card], { margin: 8 });

  await browser.close();
});
