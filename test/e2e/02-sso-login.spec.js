const { test, expect } = require('@playwright/test');

// The button's request that starts a login, with the page it was clicked on
// as return_to, but not the ?action=enabled probe.
const LOGIN_START = /\/cgi-bin\/luci-sso(\?return_to=[^&]*)?$/;

test.describe('Authentication', () => {
  test.describe('Single Sign-On', () => {
    
    test.beforeEach(async ({ context }) => {
      await context.clearCookies();
    });

    test('User logs in via the OIDC Provider', async ({ page }) => {
      
      await test.step('Given the user is on the LuCI login page', async () => {
        await page.goto('/');
        await expect(page.locator('#luci-sso-login-btn')).toBeVisible();
      });

      await test.step('When they initiate the SSO flow', async () => {
        await page.locator('#luci-sso-login-btn').click();
      });

      await test.step('Then they should be redirected back from the IdP', async () => {
        const idpHost = process.env.FQDN_IDP;
        // Escape dots for regex
        const idpRegex = idpHost.replace(/\./g, '\\.');
        await expect(page).toHaveURL(new RegExp(idpRegex + '|/cgi-bin/luci'), { timeout: 5000 });
      });

      await test.step('And they should see the authenticated dashboard', async () => {
        const logoutLink = page.locator('a[href*="/logout"]');
        await expect(logoutLink).toBeVisible();
      });

      await test.step('And they should have a valid system session cookie', async () => {
        const cookies = await page.context().cookies();
        const sessionCookie = cookies.find(c => c.name.startsWith('sysauth'));
        expect(sessionCookie).toBeDefined();
      });
    });

    // OIDC Core 3.1.3.6 makes at_hash OPTIONAL in the code flow, and some IdPs
    // (Authentik) never send it. The mock IdP leaves it out when the
    // authorization request carries its test-only omit_at_hash=1. The test
    // adds it to the redirect luci-sso answers the login button with (a
    // redirect's target is not routed, so the redirect itself is rewritten).
    test('User logs in when the ID token has no at_hash', async ({ page }) => {
      let rewritten = false;
      await page.route(LOGIN_START, async (route) => {
        const response = await route.fetch({ maxRedirects: 0 });
        const headers = response.headers();
        const target = new URL(headers['location']);
        if (target.host === process.env.FQDN_IDP) {
          target.searchParams.set('omit_at_hash', '1');
          headers['location'] = target.toString();
          rewritten = true;
        }
        await route.fulfill({ response, headers });
      });

      await test.step('Given the IdP issues ID tokens without at_hash', async () => {
        await page.goto('/');
        await expect(page.locator('#luci-sso-login-btn')).toBeVisible();
      });

      await test.step('When the user logs in through SSO', async () => {
        await page.locator('#luci-sso-login-btn').click();
      });

      await test.step('Then they see the authenticated dashboard', async () => {
        await expect(page.locator('a[href*="/logout"]')).toBeVisible();
        expect(rewritten).toBe(true);
        const cookies = await page.context().cookies();
        expect(cookies.find(c => c.name.startsWith('sysauth'))).toBeDefined();
      });
    });
  });
});
