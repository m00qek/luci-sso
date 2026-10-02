'use strict';

// Captures the LuCI screenshots used in docs/assets/screenshots/.
//
// Not a test: the name does not match Playwright's *.spec.js / *.test.js
// pattern, and devenv/scripts/test.sh only runs *.spec.js, so `make e2e-test`
// never picks it up. Run it with `make screenshots` against the CI stack
// (`make compile && make up` first). It writes PNGs to $OUT_DIR inside the
// browser container; the make target copies them into docs/assets/screenshots/.
//
// Every shot uses the same viewport and the default bootstrap theme in light
// mode, and is cropped to the page content. State is set up the way the e2e
// specs do it:
//   - the SSO settings page is fed example configuration through a mocked
//     `uci get` of luci-sso and rpcd (as in 08-sso-crud), the roles' rpcd
//     login entries included, so the images show example values rather than
//     the devenv's, and the client secret field stays masked;
//   - the read-only session sets the devenv `admin` role's rpcd login entry
//     over /ubus/ as root and applies it (as in 11-granular-roles), and
//     restores read '*' / write '*' after;
//   - the Software page's installed list gains luci-sso and its mbedtls
//     backend in the browser only, from the feed's own package index, because
//     the devenv mounts luci-sso instead of installing its package. No package
//     is installed or removed, and no dialog is confirmed.
//
// The mock IdP never appears: the SSO login redirects through it, and every
// capture is taken after the browser is back on LuCI.

const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');
const { loginAsRoot, gotoSSOSettings, loginViaSSO, applyAsRoot, entryFor, awaitAccess } = require('./helpers');

const BASE_URL = process.env.BASE_URL;
const OUT_DIR = process.env.OUT_DIR || '/tmp/luci-sso-screenshots';
const VIEWPORT = { width: 1280, height: 800 };

// Host name the router is shown under; see launch().
const EXAMPLE_HOST = 'router.example.com';

// Example configuration shown on the SSO settings page. Nothing is saved. The
// Redirect URI is left unset, so the field shows the suggestion LuCI builds
// from the address it was opened at.
const EXAMPLE_CONFIG = {
  default: {
    '.name': 'default', '.type': 'oidc', '.anonymous': false,
    enabled: '1',
    issuer_url: 'https://auth.example.com',
    client_id: 'luci-router',
    client_secret: 'example-client-secret',
    scope: 'openid profile email groups',
    clock_tolerance: '60',
  },
  admin: {
    '.name': 'admin', '.type': 'role', '.anonymous': false,
    email: ['admin@example.com'],
  },
  viewer: {
    '.name': 'viewer', '.type': 'role', '.anonymous': false,
    email: ['bob@example.com'],
    group: ['network-viewers'],
  },
};

// The read-only role from docs/how-to/sysadmin/rbac.md ("Read-only access").
const READONLY_READ = ['luci-base', 'luci-mod-status-*', 'luci-mod-network-*'];

// The example roles' rpcd login entries.
const EXAMPLE_RPCD = {
  luci_sso_admin: {
    '.name': 'luci_sso_admin', '.type': 'login', '.anonymous': false,
    username: 'sso:admin', read: ['*'], write: ['*'],
  },
  luci_sso_viewer: {
    '.name': 'luci_sso_viewer', '.type': 'login', '.anonymous': false,
    username: 'sso:viewer', read: [...READONLY_READ, 'unauthenticated'],
  },
};
const EXAMPLE = { 'luci-sso': EXAMPLE_CONFIG, rpcd: EXAMPLE_RPCD };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function newPage(browser) {
  const context = await browser.newContext({
    baseURL: browser.exampleHost ? `https://${EXAMPLE_HOST}` : BASE_URL,
    ignoreHTTPSErrors: !!browser.exampleHost,
    viewport: VIEWPORT,
    deviceScaleFactor: 1,
    colorScheme: 'light',
    locale: 'en-US',
  });
  return context.newPage();
}

async function shoot(target, name, options = {}) {
  const file = path.join(OUT_DIR, `${name}.png`);
  await target.screenshot({ path: file, animations: 'disabled', caret: 'hide', ...options });
  console.log(`  ${file}`);
}

// Sets the devenv admin role's lists as root and applies them, then waits
// until an SSO session opened before has `probe` (as 11-granular-roles).
async function setAdminLists(browser, read, write, probe) {
  // applyAsRoot opens its own context, which needs the base URL.
  const based = { newContext: (opts) => browser.newContext({ baseURL: BASE_URL, ...opts }) };
  const sso = await newPage(browser);
  try {
    await loginViaSSO(sso);
    await applyAsRoot(based, {}, entryFor('admin', read, write));
    await awaitAccess(sso, probe.group, probe.perm, probe.expected);
  } finally {
    await sso.context().close();
  }
}

// Fetches the real response for an intercepted request. Playwright makes this
// request itself, outside Chromium's host-resolver rules, so a request to
// EXAMPLE_HOST goes to the devenv name instead.
function fetchReal(route) {
  const url = new URL(route.request().url());
  if (url.hostname === EXAMPLE_HOST) url.hostname = process.env.FQDN_LUCI;
  return route.fetch({ url: url.toString() });
}

// Answers LuCI's `uci get luci-sso` and `uci get rpcd` with EXAMPLE (as
// 08-sso-crud).
async function mockSSOConfig(page) {
  await page.route(/\/ubus\/?(\?|$)/, async (route) => {
    const body = route.request().postDataJSON();
    const requests = Array.isArray(body) ? body : [body];
    const hit = requests.some(r => r?.params?.[1] === 'uci' && r?.params?.[2] === 'get' && EXAMPLE[r?.params?.[3]?.config]);
    if (!hit) return route.continue();

    const response = await fetchReal(route);
    const replies = await response.json();
    const list = Array.isArray(replies) ? replies : [replies];
    const patched = list.map((reply, i) => {
      const [, obj, method, params] = requests[i].params || [];
      if (obj === 'uci' && method === 'get' && EXAMPLE[params?.config])
        return { jsonrpc: '2.0', id: requests[i].id, result: [0, { values: EXAMPLE[params.config] }] };
      return reply;
    });
    await route.fulfill({ response, json: Array.isArray(replies) ? patched : patched[0] });
  });
}

// Adds luci-sso and its mbedtls backend to the Software page's installed list,
// using the x86_64 entries of the feed's own package index.
async function mockInstalledLuciSso(page) {
  await page.route(/\/cgi-bin\/cgi-exec/, async (route) => {
    const post = route.request().postData() || '';
    if (!decodeURIComponent(post).includes('list-installed')) return route.continue();

    const available = await page.evaluate(async () => {
      const sid = L.env.sessionid;
      const r = await fetch('/cgi-bin/cgi-exec', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `sessionid=${encodeURIComponent(sid)}&command=${encodeURIComponent('/usr/libexec/package-manager-call list-available')}`,
      });
      return r.text();
    });
    // The feed keeps older releases next to the current one, so keep only the
    // newest version of each package, as an install would pick.
    const newest = {};
    for (const block of available.split(/\n\n+/)) {
      const name = (block.match(/^Package: (luci-sso(?:-crypto-mbedtls)?)$/m) || [])[1];
      if (!name || !/^Architecture: x86_64$/m.test(block)) continue;
      const version = (block.match(/^Version: (.+)$/m) || [])[1] || '';
      const kept = newest[name];
      if (!kept || version.localeCompare(kept.version, undefined, { numeric: true }) > 0)
        newest[name] = { version, block };
    }
    const entries = Object.values(newest).map(entry => entry.block);
    if (entries.length !== 2)
      throw new Error(`expected 2 luci-sso feed entries, found ${entries.length}`);
    const installed = entries.map(block => block
      .split('\n')
      .filter(line => /^(Package|Version|Depends|Provides|Architecture|Installed-Size|Description):/.test(line) || /^ /.test(line))
      .concat(['Status: install user installed'])
      .join('\n')).join('\n\n');

    const response = await fetchReal(route);
    const text = await response.text();
    await route.fulfill({ response, body: `${text.trimEnd()}\n\n${installed}\n\n` });
  });
}

async function gotoSoftware(page, mode) {
  await page.goto('/cgi-bin/luci/admin/system/package-manager?query=luci-sso');
  await page.waitForSelector('#packages tr.tr:not(.cbi-section-table-titles)', { timeout: 20000 });
  if (mode === 'installed')
    await page.locator('li[data-mode="installed"]').click();
  await page.waitForFunction(() => !document.querySelector('#packages .spinning'));
}

// Clips a region spanning the page's content column, from `top` down to the
// bottom edge of `bottomEl`, with a margin around it.
async function contentClip(page, bottomEl, { top = 0, margin = 16 } = {}) {
  const column = await page.locator('#maincontent').boundingBox();
  const bottom = await page.locator(bottomEl).last().boundingBox();
  const x = Math.max(0, column.x - margin);
  return { x, y: top, width: Math.min(VIEWPORT.width - x, column.width + 2 * margin), height: bottom.y + bottom.height + margin - top };
}

// ---------------------------------------------------------------------------
// Shots
// ---------------------------------------------------------------------------

async function loginPage(browser) {
  const page = await newPage(browser);
  await page.goto('/');
  await page.locator('#luci-sso-login-btn').waitFor();
  const form = await page.locator('.modal.login').boundingBox();
  const margin = 24;
  await shoot(page, 'luci-login-sso-button', {
    clip: { x: form.x - margin, y: Math.max(0, form.y - margin), width: form.width + 2 * margin, height: form.height + 2 * margin },
  });
  await page.context().close();
}

async function ssoSettings(browser) {
  const page = await newPage(browser);
  await mockSSOConfig(page);
  await loginAsRoot(page);
  await gotoSSOSettings(page);
  await page.locator('.cbi-section-table-row[data-sid="viewer"]').waitFor();

  // Both sections, down to the Save & Apply bar.
  await shoot(page, 'luci-sso-settings', { fullPage: true, clip: await contentClip(page, '.cbi-page-actions') });

  // The role editor, opened from the viewer row and closed without saving.
  await page.locator('.cbi-section-table-row[data-sid="viewer"] .cbi-button-edit').click();
  const modal = page.locator('#modal_overlay .modal');
  await modal.waitFor();
  await shoot(modal, 'luci-sso-role-editor');
  await modal.getByText('Dismiss').click();
  await page.context().close();
}

// Status > Overview after an SSO login, down to the end of the System table.
async function statusOverview(browser, name) {
  const page = await newPage(browser);
  await loginViaSSO(page);
  await page.goto('/cgi-bin/luci/admin/status/overview');
  const firmware = page.locator('tr', { has: page.locator('td', { hasText: /^Firmware Version$/ }) });
  await firmware.locator('td').nth(1).getByText(/LuCI .+ branch/).waitFor({ timeout: 15000 });
  await page.locator('#view').getByText('Load Average').waitFor();
  await shoot(page, name, { clip: await contentClip(page, '.cbi-section:first-of-type table') });
  await page.context().close();
}

async function adminView(browser) {
  await statusOverview(browser, 'luci-admin-view');
}

async function readonlyView(browser) {
  await setAdminLists(browser, READONLY_READ, [], { group: 'luci-base', perm: 'write', expected: false });
  try {
    await statusOverview(browser, 'luci-readonly-view');
  } finally {
    await setAdminLists(browser, ['*'], ['*'], { group: 'luci-base', perm: 'write', expected: true });
  }
}

async function softwareAvailable(browser) {
  const page = await newPage(browser);
  await loginAsRoot(page);
  await gotoSoftware(page, 'available');
  await shoot(page, 'luci-software-install', { clip: await contentClip(page, '.controls .pager') });
  await page.context().close();
}

async function softwareInstalled(browser) {
  const page = await newPage(browser);
  await mockInstalledLuciSso(page);
  await loginAsRoot(page);
  await gotoSoftware(page, 'installed');
  await shoot(page, 'luci-software-uninstall', { clip: await contentClip(page, '.controls .pager') });
  await page.context().close();
}

// Chromium resolves router.example.com to the devenv router, so pages that
// print their own address (the Redirect URI suggestion, the Internal Issuer
// URL placeholder) show that example name. The devenv certificate is issued
// for the devenv name, hence ignoreHTTPSErrors. The SSO login cannot use this
// browser: the mock IdP only redirects back to the devenv name.
function launch(extraArgs = []) {
  return chromium.launch({
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
    args: ['--no-sandbox', '--disable-setuid-sandbox', ...extraArgs],
  });
}

async function main() {
  if (!BASE_URL || !process.env.FQDN_LUCI) throw new Error('BASE_URL and FQDN_LUCI must be set (run inside the browser container)');
  fs.mkdirSync(OUT_DIR, { recursive: true });
  console.log(`Writing screenshots to ${OUT_DIR}`);

  const router = await launch([`--host-resolver-rules=MAP ${EXAMPLE_HOST} ${process.env.FQDN_LUCI}`]);
  router.exampleHost = true;
  try {
    await loginPage(router);
    await ssoSettings(router);
    await softwareAvailable(router);
    await softwareInstalled(router);
  } finally {
    await router.close();
  }

  const devenv = await launch();
  try {
    await adminView(devenv);
    await readonlyView(devenv);
  } finally {
    await devenv.close();
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
