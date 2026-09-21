const { test, expect } = require('@playwright/test');

// Regression test for issue #11: a pre-existing LuCI session cookie at path=/cgi-bin/luci
// shadows the one luci-sso sets at Path=/, because RFC 6265 sends the longer
// path first and LuCI reads only the first value.
test('SSO login survives a stale LuCI-path session cookie (issue #11)', async ({ page, context }) => {
  await context.addCookies([{
    name: 'sysauth_https',
    value: 'deadbeefdeadbeefdeadbeefdeadbeef',
    domain: 'luci.luci-sso.test',
    path: '/cgi-bin/luci',
    secure: true,
    httpOnly: true,
  }]);

  await page.goto('/');
  await expect(page.locator('#luci-sso-login-btn')).toBeVisible();
  await page.locator('#luci-sso-login-btn').click();

  const logoutLink = page.locator('a[href*="/logout"]');
  await expect(logoutLink).toBeVisible({ timeout: 10000 });
});
