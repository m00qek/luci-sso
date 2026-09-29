const { test, expect } = require('@playwright/test');

// LuCI's own "Log out" menu entry is overridden by
// /usr/share/luci/menu.d/luci-sso-logout.json: SSO sessions are sent through
// /cgi-bin/luci-sso/logout (RP-Initiated Logout at the IdP), every other
// session gets LuCI's own logout unchanged.

const LOGOUT_LINK = 'a[href*="/admin/logout"]';

async function ssoLogin(page) {
  await page.goto('/');
  await page.locator('#luci-sso-login-btn').click();
  await page.waitForURL(/\/cgi-bin\/luci/);
  await expect(page.locator(LOGOUT_LINK).first()).toBeVisible();
}

async function passwordLogin(page) {
  await page.goto('/');
  await page.fill('input[name="luci_username"]', 'root');
  await page.fill('input[name="luci_password"]', 'admin');
  await page.click('button.cbi-button-positive');
  await page.waitForURL(/\/cgi-bin\/luci/);
  await expect(page.locator(LOGOUT_LINK).first()).toBeVisible();
}

// Records every request URL (redirect hops included) and the Set-Cookie
// headers of luci-sso's /logout response.
function record(page) {
  const seen = { urls: [], ssoLogoutCookies: [] };
  page.on('request', (r) => seen.urls.push(r.url()));
  page.on('response', async (r) => {
    if (r.url().includes('/cgi-bin/luci-sso/logout')) {
      for (const h of await r.headersArray())
        if (h.name.toLowerCase() === 'set-cookie') seen.ssoLogoutCookies.push(h.value);
    }
  });
  return seen;
}

async function sessionCookie(context) {
  return (await context.cookies()).find((c) => c.name === 'sysauth_https');
}

// Presents an old session id to LuCI: a destroyed session gets the login form.
async function expectSessionGone(page, context, sid) {
  await context.clearCookies();
  await context.addCookies([{ name: 'sysauth_https', value: sid, url: new URL('/', page.url()).href }]);
  await page.goto('/cgi-bin/luci/admin/status/overview');
  await expect(page.locator('input[name="luci_username"]')).toBeVisible();
}

test.describe("Logout: LuCI's own Log out entry", () => {
  test.beforeEach(async ({ context }) => {
    await context.clearCookies();
  });

  test('shows exactly one Log out entry with LuCI\'s title', async ({ page }) => {
    await passwordLogin(page);
    const visible = page.locator(`${LOGOUT_LINK}:visible`);
    await expect(visible).toHaveCount(1);
    await expect(visible).toHaveText(/Log out/);
  });

  test('an SSO session logs out at the router and at the IdP', async ({ page, context }) => {
    let sid;

    await test.step('Given a user logged in through SSO', async () => {
      await ssoLogin(page);
      sid = (await sessionCookie(context)).value;
      expect(sid).toBeTruthy();
    });

    const seen = record(page);

    await test.step('When they click Log out', async () => {
      await page.locator(LOGOUT_LINK).first().click();
      await expect(page.locator('input[name="luci_username"]')).toBeVisible();
    });

    await test.step('Then the browser went through luci-sso and the IdP end-session endpoint', async () => {
      const idp = process.env.FQDN_IDP;
      const hops = seen.urls;
      expect(hops.some((u) => /\/cgi-bin\/luci\/admin\/logout/.test(u))).toBeTruthy();
      expect(hops.some((u) => /\/cgi-bin\/luci-sso\/logout\?stoken=/.test(u))).toBeTruthy();

      const endSession = hops.find((u) => u.includes(idp) && new URL(u).pathname === '/logout');
      expect(endSession, `no IdP end-session request in ${JSON.stringify(hops)}`).toBeTruthy();
      const params = new URL(endSession).searchParams;
      expect(params.get('id_token_hint')).toBeTruthy();
      expect(params.get('post_logout_redirect_uri')).toMatch(/^https:\/\/.+\/$/);
    });

    await test.step('And the session cookies were cleared at both paths', async () => {
      const cleared = seen.ssoLogoutCookies.join('\n');
      expect(cleared).toMatch(/sysauth_https=;[^\n]*Path=\/;[^\n]*Max-Age=0|sysauth_https=;[^\n]*Max-Age=0[^\n]*Path=\/(;|$)/m);
      expect(cleared).toMatch(/sysauth_https=;[^\n]*Path=\/cgi-bin\/luci/);
      expect(await sessionCookie(context)).toBeUndefined();
    });

    await test.step('And the router session is destroyed', async () => {
      await expectSessionGone(page, context, sid);
    });
  });

  test('a password session logs out exactly as before', async ({ page, context }) => {
    let sid;

    await test.step('Given a user logged in with a password', async () => {
      await passwordLogin(page);
      sid = (await sessionCookie(context)).value;
      expect(sid).toBeTruthy();
    });

    const seen = record(page);

    await test.step('When they click Log out', async () => {
      await page.locator(LOGOUT_LINK).first().click();
      await expect(page.locator('input[name="luci_username"]')).toBeVisible();
    });

    await test.step('Then luci-sso and the IdP were never involved', async () => {
      // (The login page's button script still probes /cgi-bin/luci-sso?action=enabled.)
      expect(seen.urls.some((u) => u.includes('/cgi-bin/luci-sso/logout'))).toBeFalsy();
      expect(seen.urls.some((u) => u.includes(process.env.FQDN_IDP))).toBeFalsy();
    });

    await test.step('And the router session is destroyed', async () => {
      await expectSessionGone(page, context, sid);
    });
  });
});
