const { test, expect } = require('@playwright/test');

test.describe('Authentication', () => {
  test.describe('Local Credentials', () => {

    test.beforeEach(async ({ context }) => {
      await context.clearCookies();
    });

    test('User logs in with root/admin', async ({ page }) => {

      await test.step('Given the user is on the LuCI login page', async () => {
        await page.goto('/');
      });

      await test.step('When they provide valid root credentials', async () => {
        await page.fill('input[name="luci_username"]', 'root');
        await page.fill('input[name="luci_password"]', 'admin');
        await page.click('button.cbi-button-positive');
      });

      await test.step('Then they should be granted access', async () => {
        await expect(page).toHaveURL(/\/cgi-bin\/luci\/?/);
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