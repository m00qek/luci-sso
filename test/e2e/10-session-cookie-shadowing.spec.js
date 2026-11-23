const { test, expect } = require('@playwright/test');

// Issue #11: LuCI reads only the first value of its session cookie, and
// RFC 6265 sends the cookie with the longer path first. A session cookie that
// LuCI's own password login left at its path therefore shadows the one
// luci-sso sets at Path=/, and the page after an SSO login runs under the old
// session. LuCI sets its cookie at path=build_url(), i.e. /cgi-bin/luci/ with
// a trailing slash; earlier luci-sso releases expired only /cgi-bin/luci.

const LOGOUT_LINK = 'a[href*="/admin/logout"]';
const SESSION_COOKIES = ['sysauth_https', 'sysauth_http', 'sysauth'];

async function passwordLogin(page) {
  await page.goto('/');
  await page.fill('input[name="luci_username"]', 'root');
  await page.fill('input[name="luci_password"]', 'admin');
  await page.click('button.cbi-button-positive');
  await page.waitForURL(/\/cgi-bin\/luci/);
  await expect(page.locator(LOGOUT_LINK).first()).toBeVisible();
}

// The SSO button is offered on LuCI's login page. A live password session
// skips that page, so it is reached at /cgi-bin/luci-sso directly, which is
// where the button sends the browser.
async function ssoLogin(page) {
  await page.goto('/cgi-bin/luci-sso');
  await page.waitForURL(/\/cgi-bin\/luci\//);
  await expect(page.locator(LOGOUT_LINK).first()).toBeVisible();
}

const pageSession = (page) => page.evaluate(() => L.env.sessionid);

async function sessionCookies(context) {
  return (await context.cookies()).filter((c) => SESSION_COOKIES.includes(c.name));
}

// What LuCI does with the browser's cookies now: the login form, or a page.
async function expectLoggedOut(page) {
  await page.goto('/cgi-bin/luci/admin/status/overview');
  await expect(page.locator('input[name="luci_username"]')).toBeVisible();
}

test.describe('SSO login over an existing LuCI session (issue #11)', () => {
  test.beforeEach(async ({ context }) => {
    await context.clearCookies();
  });

  test('the SSO session replaces a password session in the same browser, and logout ends both', async ({ page, context }) => {
    let rootSid;
    let ssoSid;

    await test.step('Given a browser logged in to LuCI with a password', async () => {
      await passwordLogin(page);
      rootSid = await pageSession(page);
      expect(rootSid).toMatch(/^[0-9a-f]{32}$/);
      const own = (await sessionCookies(context)).find((c) => c.value === rootSid);
      expect(own, 'LuCI set its own session cookie').toBeTruthy();
      expect(own.path).toBe('/cgi-bin/luci/');
    });

    await test.step('When the same browser logs in through SSO, keeping its cookies', async () => {
      await ssoLogin(page);
      const set = (await sessionCookies(context)).find((c) => c.name === 'sysauth_https' && c.path === '/');
      expect(set, 'luci-sso set its session cookie at Path=/').toBeTruthy();
      ssoSid = set.value;
      expect(ssoSid).not.toBe(rootSid);
    });

    await test.step('Then the page runs under the SSO session', async () => {
      expect(await pageSession(page)).toBe(ssoSid);
    });

    await test.step('And no cookie carries the password session any more', async () => {
      const left = (await sessionCookies(context)).filter((c) => c.value === rootSid);
      expect(left, JSON.stringify(left)).toEqual([]);
    });

    await test.step('When the user logs out', async () => {
      await page.locator(LOGOUT_LINK).first().click();
      await expect(page.locator('input[name="luci_username"]')).toBeVisible();
    });

    await test.step('Then the browser holds no session cookie of either login', async () => {
      const left = (await sessionCookies(context)).filter((c) => c.value === rootSid || c.value === ssoSid);
      expect(left, JSON.stringify(left)).toEqual([]);
    });

    await test.step('And LuCI asks the browser to log in again', async () => {
      await expectLoggedOut(page);
    });
  });

  // Cookies an earlier luci-sso release, or another setup, left at the
  // slashless path shadow the new session the same way.
  for (const path of ['/cgi-bin/luci/', '/cgi-bin/luci']) {
    test(`an SSO login survives a stale session cookie at ${path}`, async ({ page, context }) => {
      await context.addCookies(SESSION_COOKIES.map((name) => ({
        name,
        value: 'deadbeefdeadbeefdeadbeefdeadbeef',
        domain: new URL(process.env.BASE_URL).hostname,
        path,
        secure: true,
        httpOnly: true,
      })));

      await page.goto('/');
      await page.locator('#luci-sso-login-btn').click();
      await expect(page.locator(LOGOUT_LINK).first()).toBeVisible({ timeout: 10000 });

      const stale = (await sessionCookies(context)).filter((c) => c.value === 'deadbeefdeadbeefdeadbeefdeadbeef');
      expect(stale, JSON.stringify(stale)).toEqual([]);
    });
  }
});
