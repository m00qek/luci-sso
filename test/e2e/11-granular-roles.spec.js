'use strict';
const { test, expect } = require('@playwright/test');
const { applyAsRoot, entryFor, awaitAccess, loginViaSSO: ssoLogin, RELOAD_WAIT_MS } = require('./helpers');

// Granular SSO roles against the real rpcd.
//
// The mock IdP always signs in admin@example.com, which the devenv maps to the
// `admin` role. That role's permissions are its rpcd login entry,
// rpcd.luci_sso_admin (username sso:admin). This spec sets its lists as root
// over /ubus/ and applies them before each case, and restores read '*' /
// write '*' afterwards. Each change makes rpcd reload, and the spec waits
// until an open SSO session has the new rights, so that no step races rpcd's
// restart.
//
// luci-sso expands the entry's access groups into the concrete ubus/uci grants
// rpcd gives a password login with the same lists. Without that expansion an
// SSO session holds only access-group names, rpcd refuses every data call,
// and the overview below renders without its values.

// Calls rpcd over /ubus/ with the page's own LuCI session and returns
// { status, data }. rpcd refuses a call the session's ACL does not allow with
// a JSON-RPC error (-32002 "Access denied") rather than a ubus status, so that
// becomes status 'denied', as does the uci plugin's own ubus status 6
// (UBUS_STATUS_PERMISSION_DENIED). LuCI sessions may not `uci commit`; they stage
// changes and `uci apply` them.
//
// A call that reaches rpcd while it restarts is never answered, so each call
// gives up after two seconds and reports status 'timeout'.
async function ubus(page, obj, method, params) {
  const reply = await page.evaluate(async ([o, m, p]) => {
    try {
      const r = await fetch('/ubus/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'call', params: [L.env.sessionid, o, m, p] }),
        signal: AbortSignal.timeout(2000),
      });
      return await r.json();
    } catch (e) {
      return { error: { code: 'timeout' } };
    }
  }, [obj, method, params]);
  if (reply.error)
    return { status: reply.error.code === -32002 ? 'denied' : reply.error.code, data: null };
  // The uci plugin refuses a scope it checks itself with UBUS_STATUS_PERMISSION_DENIED.
  return { status: reply.result[0] === 6 ? 'denied' : reply.result[0], data: reply.result[1] };
}

// Sets the read/write lists of the devenv admin role as root and applies
// them, then waits until an SSO session opened before has `probe`: the new
// rights are in force.
async function setRole(browser, read, write, probe) {
  const sso = await browser.newPage();
  try {
    await ssoLogin(sso);
    await applyAsRoot(browser, {}, entryFor('admin', read, write));
    await awaitAccess(sso, probe.group, probe.perm, probe.expected);
  } finally {
    await sso.close();
  }
}

async function loginViaSSO(page) {
  await page.context().clearCookies();
  await page.goto('/');
  await page.locator('#luci-sso-login-btn').click();
  await expect(page.locator('a[href*="/logout"]')).toBeVisible({ timeout: 5000 });
}

test.describe('SSO roles: access groups work like a password login', () => {
  // Each test and the hook wait for one reload, which may take RELOAD_WAIT_MS.
  test.describe.configure({ timeout: RELOAD_WAIT_MS + 30000 });

  test.afterAll(async ({ browser }) => {
    test.setTimeout(RELOAD_WAIT_MS + 30000);
    await setRole(browser, ['*'], ['*'], { group: 'luci-mod-network-config', perm: 'write', expected: true });
  });

  test("read '*' only: the overview shows real data, and nothing can be changed", async ({ page, browser }) => {
    await setRole(browser, ['*'], [], { group: 'luci-base', perm: 'write', expected: false });
    await loginViaSSO(page);

    await test.step('Status > Overview loads its data', async () => {
      // The firmware row includes LuCI's own version, from luci.getVersion: a
      // call the session can only make with the expanded grants. (The devenv
      // container reports no hostname or kernel, so those rows read "?" even
      // for root.)
      await page.goto('/cgi-bin/luci/admin/status/overview');
      const firmware = page.locator('tr', { has: page.locator('td', { hasText: /^Firmware Version$/ }) });
      await expect(firmware.locator('td').nth(1)).toContainText(/LuCI .+ branch/, { timeout: 10000 });
    });

    await test.step('reading configuration works', async () => {
      expect((await ubus(page, 'uci', 'get', { config: 'system' })).status).toBe(0);
    });

    await test.step('saving is refused', async () => {
      expect((await ubus(page, 'uci', 'set', { config: 'system', section: '@system[0]', values: { hostname: 'pwned' } })).status).toBe('denied');
    });

    await test.step('raw file access is refused', async () => {
      expect((await ubus(page, 'file', 'read', { path: '/etc/shadow' })).status).toBe('denied');
    });
  });

  // luci-base's write section grants the uci set/apply calls themselves; a
  // group like luci-mod-system-config grants write on its configs. A writer
  // needs both, exactly as an rpcd password login would.
  test('write luci-mod-system-config: system settings can be saved, network settings cannot', async ({ page, browser }) => {
    await setRole(browser, ['*'], ['luci-base', 'luci-mod-system-config'], { group: 'luci-mod-system-config', perm: 'write', expected: true });
    await loginViaSSO(page);

    await test.step('the System page loads', async () => {
      await page.goto('/cgi-bin/luci/admin/system/system');
      await expect(page.locator('.cbi-map')).toBeVisible({ timeout: 10000 });
    });

    await test.step('a system change is accepted', async () => {
      // Staged in this session only; never applied.
      expect((await ubus(page, 'uci', 'set', { config: 'system', section: '@system[0]', values: { zonename: 'UTC' } })).status).toBe(0);
    });

    await test.step('a network change is refused', async () => {
      expect((await ubus(page, 'uci', 'set', { config: 'network', section: 'loopback', values: { mtu: '1400' } })).status).toBe('denied');
    });
  });
});
