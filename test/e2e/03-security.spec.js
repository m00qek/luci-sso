const { test, expect } = require('@playwright/test');

test.describe('Security: OIDC Attacks', () => {
  
  test.beforeEach(async ({ context }) => {
    await context.clearCookies();
  });

  test('Token Replay: Reusing an authorization response should fail', async ({ page }) => {
    let callbackUrl;

    await test.step('Given a user completes the OIDC flow once', async () => {
      console.log('Starting first login attempt...');
      await page.goto('/');
      await page.locator('#luci-sso-login-btn').click();
      
      console.log('Waiting for successful auth and redirect...');
      // Wait for the IdP or the final LuCI dashboard
      await page.waitForURL(/\/cgi-bin\/luci/, { timeout: 15000 });
      callbackUrl = page.url();
      console.log(`Captured callback URL: ${callbackUrl}`);
      
      await expect(page.locator('a[href*="/logout"]')).toBeVisible();
      console.log('First login successful.');
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

  test('Authorization Code Replay: Reusing a code with a fresh session should fail', async ({ page, context }) => {
    let oldCode;

    await test.step('Given a user captures an authorization code from a successful flow', async () => {
      console.log('Capture step: Setting up request listener');
      // Use request interception to catch the code as it flies by
      const codePromise = page.waitForRequest(request => {
        return request.url().includes('code=') && request.url().includes('luci-sso/callback');
      }, { timeout: 20000 });

      await page.goto('/');
      await page.waitForSelector('#luci-sso-login-btn', { timeout: 10000 });
      await page.locator('#luci-sso-login-btn').click();
      
      const callbackRequest = await codePromise;
      const url = new URL(callbackRequest.url());
      oldCode = url.searchParams.get('code');
      console.log(`Capture step: Captured code: ${oldCode}`);
      expect(oldCode).toBeTruthy();
      
      // Allow the flow to complete (consume the code)
      await page.waitForURL(/.*\/cgi-bin\/luci($|\?|\/).*/, { timeout: 20000 });
      console.log('Capture step: Flow completed');
    });

    await test.step('When the user starts a NEW flow but attempts to reuse the OLD code', async () => {
      console.log('Replay step: Clearing cookies');
      await context.clearCookies();
      
      // Start a new flow to get a fresh state cookie
      await page.goto('/');
      await page.waitForSelector('#luci-sso-login-btn', { timeout: 10000 });
      await page.locator('#luci-sso-login-btn').click();
      
      // Wait until we reach the IdP
      await page.waitForURL(/.*idp\.luci-sso\.test.*/, { timeout: 20000 });
      
      const cookies = await context.cookies();
      const stateCookie = cookies.find(c => c.name === 'luci_sso_state');
      expect(stateCookie).toBeDefined();

      // Attempt to call the callback with the OLD code but the NEW state cookie
      const callbackUrl = `/cgi-bin/luci-sso/callback?code=${oldCode}&state=anything`;
      console.log(`Replay step: Replaying to ${callbackUrl}`);
      await page.goto(callbackUrl);
    });

    await test.step('Then the system should reject the reuse of the expired/consumed code', async () => {
      console.log('Verification step: Checking for login rejection');
      // Should be back at login
      await expect(page.locator('#luci-sso-login-btn')).toBeVisible({ timeout: 10000 });
      await expect(page.locator('a[href*="/logout"]')).not.toBeVisible();
      console.log('Verification step: Success');
    });
  });
});
