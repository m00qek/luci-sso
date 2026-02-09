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
});
