const { test, expect } = require('@playwright/test');

// Issue #27. LuCI shows its login page at the address that was asked for, and
// its password login then opens that page. An SSO login must do the same: the
// button passes the page as return_to, the router keeps it in the handshake,
// and the callback redirects there. A return_to that is not a LuCI page is
// dropped, and the login lands on /cgi-bin/luci/ as before.

const DEEP_PAGE = '/cgi-bin/luci/admin/services/sso';

// Records the Location of every callback response. A redirect's target is not
// routed by Playwright, so the callback is observed rather than intercepted.
function recordCallbackRedirects(page) {
  const locations = [];
  page.on('response', (response) => {
    if (new URL(response.url()).pathname === '/cgi-bin/luci-sso/callback')
      locations.push(response.headers()['location']);
  });
  return locations;
}

test.describe('Single Sign-On: return to the requested page', () => {

  test.beforeEach(async ({ context }) => {
    await context.clearCookies();
  });

  test('A logged-out user who opens a deep link lands on it after an SSO login', async ({ page }) => {
    const callbacks = recordCallbackRedirects(page);

    await test.step('Given a logged-out user opens a LuCI page by its address', async () => {
      await page.goto(DEEP_PAGE);
      await expect(page.locator('#luci-sso-login-btn')).toBeVisible();
      expect(new URL(page.url()).pathname).toBe(DEEP_PAGE);
    });

    await test.step('When they log in with SSO', async () => {
      await page.locator('#luci-sso-login-btn').click();
      await expect(page.locator('a[href*="/logout"]')).toBeVisible();
    });

    await test.step('Then the callback sends them to that page, and it opens', async () => {
      expect(callbacks).toEqual([DEEP_PAGE]);
      expect(new URL(page.url()).pathname).toBe(DEEP_PAGE);
      await expect(page.locator('.cbi-map')).toBeVisible();
    });
  });

  for (const hostile of ['https://evil.example/', '//evil.example/', '/cgi-bin/luci/%2e%2e/%2e%2e/evil']) {
    test(`A hand-made return_to ${hostile} lands on /cgi-bin/luci/`, async ({ page }) => {
      const callbacks = recordCallbackRedirects(page);

      await page.goto('/cgi-bin/luci-sso?return_to=' + encodeURIComponent(hostile));
      await expect(page.locator('a[href*="/logout"]')).toBeVisible();

      expect(callbacks).toEqual(['/cgi-bin/luci/']);
      const landed = new URL(page.url());
      expect(landed.host).toBe(new URL(process.env.BASE_URL).host);
      expect(landed.pathname.startsWith('/cgi-bin/luci/')).toBe(true);
    });
  }

  // LuCI runs its logout for any path under admin/logout, not only the exact
  // one, so a crafted link could log the victim straight out again (and out
  // of the IdP, through RP-initiated logout).
  for (const logout of ['/cgi-bin/luci/admin/logout/x', '/cgi-bin/luci/admin/logout%2Fx']) {
    test(`A crafted return_to ${logout} does not log the user out`, async ({ page }) => {
      const callbacks = recordCallbackRedirects(page);

      await test.step('Given a link that returns to a path under LuCI\'s logout page', async () => {
        await page.goto('/cgi-bin/luci-sso?return_to=' + encodeURIComponent(logout));
        await expect(page.locator('a[href*="/logout"]')).toBeVisible();
      });

      await test.step('Then the login lands on /cgi-bin/luci/, and the session stays', async () => {
        expect(callbacks).toEqual(['/cgi-bin/luci/']);
        await page.goto(DEEP_PAGE);
        expect(new URL(page.url()).pathname).toBe(DEEP_PAGE);
        await expect(page.locator('.cbi-map')).toBeVisible();
        await expect(page.locator('#luci-sso-login-btn')).toHaveCount(0);
      });
    });
  }
});
