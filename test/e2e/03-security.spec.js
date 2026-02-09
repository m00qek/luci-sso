const { test, expect } = require('@playwright/test');

const vlog = (msg) => {
  if (process.env.VERBOSE) {
    console.log(`[DEBUG] ${msg}`);
  }
};

test.describe('Security: OIDC Attacks', () => {
  
  test.beforeEach(async ({ context }) => {
    await context.clearCookies();
  });

  test('Token Replay: Reusing an authorization response should fail', async ({ page }) => {
    let callbackUrl;

    await test.step('Given a user completes the OIDC flow once', async () => {
      vlog('Starting first login attempt...');
      await page.goto('/');
      await page.locator('#luci-sso-login-btn').click();
      
      vlog('Waiting for successful auth and redirect...');
      // Wait for the IdP or the final LuCI dashboard
      await page.waitForURL(/\/cgi-bin\/luci/, { timeout: 5000 });
      callbackUrl = page.url();
      vlog(`Captured callback URL: ${callbackUrl}`);
      
      await expect(page.locator('a[href*="/logout"]')).toBeVisible({ timeout: 5000 });
      vlog('First login successful.');
    });

    await test.step('When the user attempts to replay the EXACT same callback URL', async () => {
      // Clear session cookies to simulate a new attempt with the old URL
      await page.context().clearCookies();
      
      // Attempt to navigate to the same callback URL again
      await page.goto(callbackUrl);
    });

    await test.step('Then the system should reject the replayed request', async () => {
      // We expect NOT to be logged in
      await expect(page.locator('a[href*="/logout"]')).not.toBeVisible();
      
      // Instead, we expect to be back at the login page (standard LuCI fallback)
      // The login page has the username/password fields and the SSO button
      await expect(page.locator('input[name="luci_username"]')).toBeVisible();
      await expect(page.locator('#luci-sso-login-btn')).toBeVisible();
    });
  });

  test('Authorization Code Replay: Reusing a code with a fresh session should fail', async ({ request, context }) => {
    let oldCode;

    await test.step('Given a user captures an authorization code from a successful flow', async () => {
      vlog('Capture step: Starting flow via Request API');
      
      // 1. Get the landing page to start flow (DO NOT FOLLOW REDIRECTS)
      const res = await request.get('/cgi-bin/luci-sso', { maxRedirects: 0 });
      expect(res.status()).toBe(302);
      
      const loc = res.headers()['location'];
      const idpUrl = new URL(loc);
      oldCode = 'captured-via-idp-simulation'; // We need a real code from the IdP

      // Actually, we can just use the page to get a real code once
      const page = await context.newPage();
      await page.goto('/');
      
      const capturePromise = page.waitForRequest(r => r.url().includes('/callback?code='));
      await page.locator('#luci-sso-login-btn').click();
      const capReq = await capturePromise;
      oldCode = new URL(capReq.url()).searchParams.get('code');
      
      vlog(`Capture step: Captured code: ${oldCode}`);
      await page.close();
    });

    await test.step('When the user starts a NEW flow and replays the OLD code', async () => {
      vlog('Replay step: Initializing fresh handshake');
      
      // 1. Start fresh flow to get a NEW state cookie (DO NOT FOLLOW REDIRECTS)
      const initRes = await request.get('/cgi-bin/luci-sso', { maxRedirects: 0 });
      expect(initRes.status()).toBe(302);
      
      const setCookie = initRes.headers()['set-cookie'];
      const stateCookie = setCookie.split(';')[0];
      vlog(`Replay step: Fresh state cookie: ${stateCookie}`);

      // 2. Extract the NEW state value from the redirect location
      const idpUrl = new URL(initRes.headers()['location']);
      const newState = idpUrl.searchParams.get('state');
      vlog(`Replay step: Fresh state value: ${newState}`);

      // 3. Replay OLD code with NEW state and NEW cookie
      const callbackUrl = `/cgi-bin/luci-sso/callback?code=${oldCode}&state=${newState}`;
      vlog(`Replay step: Replaying to ${callbackUrl}`);

      const replayRes = await request.get(callbackUrl, {
        headers: { 'Cookie': stateCookie },
        maxRedirects: 0
      });

      vlog(`Replay step: Received status: ${replayRes.status()}`);
      const body = await replayRes.text();
      
      // We expect an error because the code is replayed.
      // If uhttpd swallowed the 500 status and gave us 200, we check the body for 'Error:'
      const isRejected = replayRes.status() >= 400 || body.includes('Error:');
      
      if (!isRejected) {
        vlog(`Replay step: UNEXPECTED SUCCESS BODY: ${body}`);
      }
      
      expect(isRejected).toBeTruthy();
    });

    await test.step('Then the system should have rejected the request', async () => {
      vlog('Verification step: Success');
    });
  });

  test('PKCE Protection: Reusing a code with a different session must fail', async ({ request, context }) => {
    let codeA;

    await test.step('Given a user captures a code from Session A', async () => {
      const page = await context.newPage();
      await page.goto('/');
      
      const capturePromise = page.waitForRequest(r => r.url().includes('/callback?code='));
      await page.locator('#luci-sso-login-btn').click();
      const capReq = await capturePromise;
      codeA = new URL(capReq.url()).searchParams.get('code');
      
      vlog(`Capture A: code=${codeA}`);
      await page.close();
    });

    await test.step('When the user attempts to use codeA with a fresh Session B', async () => {
      // 1. Initialize Session B
      const initRes = await request.get('/cgi-bin/luci-sso', { maxRedirects: 0 });
      const stateCookieB = initRes.headers()['set-cookie'].split(';')[0];
      const stateB = new URL(initRes.headers()['location']).searchParams.get('state');
      
      vlog(`Session B initialized: state=${stateB}`);

      // 2. Attempt to use codeA with sessionB
      const callbackUrl = `/cgi-bin/luci-sso/callback?code=${codeA}&state=${stateB}`;
      const replayRes = await request.get(callbackUrl, {
        headers: { 'Cookie': stateCookieB },
        maxRedirects: 0
      });

      vlog(`Replay result: status=${replayRes.status()}`);
      const body = await replayRes.text();
      
      // Verification: IdP (Mock) should reject verifierB for codeA (which is tied to challengeA)
      const isRejected = replayRes.status() >= 400 || body.includes('Error:');
      expect(isRejected).toBeTruthy();
    });

    await test.step('Then the system should have rejected the cross-session code swap', async () => {
      vlog('Verification step: Success');
    });
  });
});
