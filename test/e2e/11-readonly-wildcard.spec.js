'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot } = require('./helpers');

// A role with `list read '*'` and no write must not get admin rights. It used
// to: any `*` counted as the admin wildcard, which also granted raw ubus, uci,
// file and cgi-io access and write on every LuCI group.
//
// This spec checks only what such a session must NOT be able to do. rpcd turns
// access-group grants into concrete ubus/uci rights only for password logins,
// so an SSO session holding read grants cannot yet read through /ubus/ either;
// that is a separate, known limitation of non-admin SSO roles.
//
// The mock IdP always signs in admin@example.com, which the devenv maps to the
// `admin` role (read '*', write '*'). This spec removes that role's write list
// for the duration of the test, as root, and puts it back afterwards.

// Calls rpcd over /ubus/ with the page's own LuCI session and returns
// { status, data }. rpcd refuses a call the session's ACL does not allow with
// a JSON-RPC error (-32002 "Access denied") rather than a ubus status, so that
// becomes status 'denied'. LuCI sessions may not `uci commit`; they stage
// changes and `uci apply` them.
async function ubus(page, obj, method, params) {
  const reply = await page.evaluate(async ([o, m, p]) => {
    const r = await fetch('/ubus/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'call', params: [L.env.sessionid, o, m, p] }),
    });
    return r.json();
  }, [obj, method, params]);
  if (reply.error)
    return { status: reply.error.code === -32002 ? 'denied' : reply.error.code, data: null };
  return { status: reply.result[0], data: reply.result[1] };
}

async function asRoot(browser, fn) {
  const context = await browser.newContext();
  const page = await context.newPage();
  try {
    await loginAsRoot(page);
    await fn(page);
  } finally {
    await context.close();
  }
}

test.describe('Security: read-only wildcard role', () => {
  test.beforeAll(async ({ browser }) => {
    await asRoot(browser, async (page) => {
      expect((await ubus(page, 'uci', 'delete', { config: 'luci-sso', section: 'admin', option: 'write' })).status).toBe(0);
      expect((await ubus(page, 'uci', 'apply', { rollback: false })).status).toBe(0);
    });
  });

  test.afterAll(async ({ browser }) => {
    await asRoot(browser, async (page) => {
      expect((await ubus(page, 'uci', 'set', { config: 'luci-sso', section: 'admin', values: { write: ['*'] } })).status).toBe(0);
      expect((await ubus(page, 'uci', 'apply', { rollback: false })).status).toBe(0);
    });
  });

  test("an SSO user with read '*' and no write gets no write or raw access", async ({ page, context }) => {
    await context.clearCookies();

    await test.step('Given the user signs in via SSO', async () => {
      await page.goto('/');
      await page.locator('#luci-sso-login-btn').click();
      await expect(page.locator('a[href*="/logout"]')).toBeVisible({ timeout: 5000 });
    });

    await test.step('Then a configuration change is refused by rpcd', async () => {
      const r = await ubus(page, 'uci', 'set', { config: 'system', section: '@system[0]', values: { hostname: 'pwned' } });
      expect(r.status).toBe('denied');
    });

    await test.step('And raw file access is refused', async () => {
      const r = await ubus(page, 'file', 'read', { path: '/etc/shadow' });
      expect(r.status).toBe('denied');
    });
  });
});
