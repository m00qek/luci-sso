const { test, expect } = require('@playwright/test');

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
  });
});
