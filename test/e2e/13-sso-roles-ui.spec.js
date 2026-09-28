'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot, gotoSSOSettings, loginViaSSO, ubus, listRoles, RELOAD_WAIT_MS } = require('./helpers');

// The Users section of the SSO settings page against the real rpcd: matching
// rules and order in /etc/config/luci-sso (UCI), permissions in each role's
// rpcd login entry (the luci-sso ubus object). Every role created here is
// named e2e_*; the devenv's `admin` role is left as it is.
//
// The mock IdP always signs in admin@example.com, which the devenv's `admin`
// role matches. A role created here that matches the same email decides the
// SSO session's rights once it is moved above `admin`: the first match wins.

const READONLY_READ = ['luci-base', 'luci-mod-status-*', 'luci-mod-network-*'];

function row(page, sid) {
    return page.locator(`.cbi-section-table-row[data-sid="${sid}"]`);
}

function modal(page) {
    return page.locator('#modal_overlay .modal');
}

// Types the values into a DynamicList of the open modal, one entry each.
async function fillList(page, name, values) {
    const field = modal(page).locator(`[data-name="${name}"]`);
    for (const v of values) {
        await field.locator('input[type="text"]').last().fill(v);
        await field.locator('.cbi-button-add').click();
    }
}

async function addRole(page, name, { emails = [], read = [], write = [] }) {
    await page.locator('.cbi-section-create-name').pressSequentially(name);
    await page.locator('.cbi-section-create .cbi-button-add').click();
    await expect(modal(page)).toBeVisible();
    // The dialog's own Save does not write the permissions: the page says so.
    await expect(modal(page).locator('.luci-sso-access-note'))
        .toHaveText('Permission changes take effect when you click Save at the bottom of the page.');
    await fillList(page, 'email', emails);
    await fillList(page, 'read', read);
    await fillList(page, 'write', write);
    await modal(page).locator('button.cbi-button-positive').click();
    await expect(modal(page)).toBeHidden();
}

// Save & Apply: the page writes the permissions and waits for rpcd to reload
// (when `access` changed), then LuCI applies the UCI changes, confirms them
// and reloads the page. The apply must be confirmed before the test moves on,
// or LuCI rolls it back.
async function saveAndApply(page, { access = true } = {}) {
    await page.locator('.cbi-page-actions .cbi-button-apply').first().click();
    if (access)
        await expect(page.locator('.alert-message', { hasText: 'Role permissions saved and in force.' })).toBeVisible({ timeout: RELOAD_WAIT_MS });
    const applied = page.getByText('Configuration changes applied.');
    const none = page.getByText('There are no changes to apply');
    await expect(applied.or(none)).toBeVisible({ timeout: 60000 });
    if (await applied.isVisible())
        await page.waitForEvent('load', { timeout: 30000 });
    await expect(page.getByText('Session expired')).toHaveCount(0);
}

// The committed role order in /etc/config/luci-sso.
async function roleOrder(page) {
    const r = await ubus(page, 'uci', 'get', { config: 'luci-sso', type: 'role' });
    return Object.values(r.data.values).sort((a, b) => a['.index'] - b['.index']).map(s => s['.name']);
}

async function cleanup(browser) {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
        await loginAsRoot(page);
        const r = await ubus(page, 'uci', 'get', { config: 'luci-sso', type: 'role' });
        for (const name of Object.keys(r.data?.values ?? {}).filter(n => n.startsWith('e2e_')))
            await ubus(page, 'uci', 'delete', { config: 'luci-sso', section: name });
        await ubus(page, 'uci', 'apply', { rollback: false });
        for (const name of Object.keys(await listRoles(page)).filter(n => n.startsWith('e2e_')))
            await ubus(page, 'luci-sso', 'delete_role', { name });
        await listRoles(page);
    } finally {
        await context.close();
    }
}

// A save waits for an rpcd reload, which may take RELOAD_WAIT_MS.
test.describe.configure({ mode: 'serial', timeout: RELOAD_WAIT_MS + 30000 });

test.describe('SSO settings: roles and their rpcd permissions', () => {
    test.beforeAll(async ({ browser }) => { test.setTimeout(RELOAD_WAIT_MS + 30000); await cleanup(browser); });
    test.afterAll(async ({ browser }) => { test.setTimeout(RELOAD_WAIT_MS + 30000); await cleanup(browser); });

    test('creating a role writes the luci-sso role and its rpcd entry, with unauthenticated', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await page.locator('.cbi-section-create-name').pressSequentially('e2e_viewer');
        await page.locator('.cbi-section-create .cbi-button-add').click();
        await expect(modal(page).locator('[data-name="read"]')).toContainText('unauthenticated is always included');
        await fillList(page, 'email', ['viewer@example.com']);
        await fillList(page, 'read', ['luci-mod-status-*']);
        await modal(page).locator('button.cbi-button-positive').click();
        await expect(modal(page)).toBeHidden();

        await expect(row(page, 'e2e_viewer').locator('td[data-name="_read"]')).toHaveText('luci-mod-status-*');
        await saveAndApply(page);

        expect((await listRoles(page)).e2e_viewer).toEqual({ read: ['luci-mod-status-*', 'unauthenticated'], write: [] });
        await expect.poll(async () => (await roleOrder(page)).includes('e2e_viewer'), { timeout: 10000 }).toBe(true);
        const email = await ubus(page, 'uci', 'get', { config: 'luci-sso', section: 'e2e_viewer', option: 'email' });
        expect(email.data.value).toEqual(['viewer@example.com']);
    });

    test('editing a role rewrites its rpcd entry; the table hides unauthenticated', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await row(page, 'e2e_viewer').locator('.cbi-button-edit').click();
        await expect(modal(page)).toBeVisible();
        // The stored list is luci-mod-status-* and unauthenticated; the editor shows the first only.
        await expect(modal(page).locator('[data-name="read"] .item')).toHaveText(['luci-mod-status-*']);
        await fillList(page, 'read', ['luci-base']);
        await fillList(page, 'write', ['luci-mod-system-config']);
        await modal(page).locator('button.cbi-button-positive').click();
        await expect(modal(page)).toBeHidden();
        await expect(row(page, 'e2e_viewer').locator('td[data-name="_read"]')).toHaveText('luci-mod-status-*, luci-base');
        await saveAndApply(page);

        expect((await listRoles(page)).e2e_viewer).toEqual({
            read: ['luci-mod-status-*', 'luci-base', 'unauthenticated'], write: ['luci-mod-system-config'],
        });
    });

    test('a role with no access groups is saved with unauthenticated only, and the page warns about it', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await addRole(page, 'e2e_none', { emails: ['nobody@example.com'] });
        await expect(row(page, 'e2e_none').locator('td[data-name="_read"]')).toHaveText('(none): this role grants no access');
        await saveAndApply(page);

        expect((await listRoles(page)).e2e_none).toEqual({ read: ['unauthenticated'], write: [] });
        await gotoSSOSettings(page);
        await expect(row(page, 'e2e_none').locator('td[data-name="_read"]')).toHaveText('(none): this role grants no access');
    });

    test('the first matching role wins, and dragging a role above another changes which one', async ({ page, browser }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        // A read-only role for the same user as `admin`, added below it.
        await addRole(page, 'e2e_ro', { emails: ['admin@example.com'], read: READONLY_READ });
        await saveAndApply(page);
        expect((await listRoles(page)).e2e_ro).toEqual({ read: [...READONLY_READ, 'unauthenticated'], write: [] });

        const sso = await browser.newPage();
        await test.step('below admin: the SSO user gets admin and may save', async () => {
            await loginViaSSO(sso);
            expect((await ubus(sso, 'uci', 'set', { config: 'system', section: '@system[0]', values: { zonename: 'UTC' } })).status).toBe(0);
        });

        await test.step('drag e2e_ro above admin and apply', async () => {
            await gotoSSOSettings(page);
            await row(page, 'e2e_ro').locator('.drag-handle').dragTo(row(page, 'admin'));
            await saveAndApply(page, { access: false });
            await expect.poll(async () => {
                const order = await roleOrder(page);
                return order.indexOf('e2e_ro') < order.indexOf('admin');
            }, { timeout: 10000 }).toBe(true);
        });

        await test.step('above admin: the SSO user gets the read-only role', async () => {
            await loginViaSSO(sso);
            await sso.goto('/cgi-bin/luci/admin/status/overview');
            const firmware = sso.locator('tr', { has: sso.locator('td', { hasText: /^Firmware Version$/ }) });
            await expect(firmware.locator('td').nth(1)).toContainText(/LuCI .+ branch/, { timeout: 10000 });
            expect((await ubus(sso, 'uci', 'set', { config: 'system', section: '@system[0]', values: { zonename: 'UTC' } })).status).toBe('denied');
        });

        await test.step('LuCI never reports the session as expired: the entry holds unauthenticated', async () => {
            await sso.goto('/cgi-bin/luci/admin/status/routes');
            await sso.waitForLoadState('networkidle');
            await sso.waitForTimeout(2000);
            await expect(sso.getByText('Session expired')).toHaveCount(0);
            expect((await ubus(sso, 'session', 'access', { scope: 'ubus', object: 'luci', function: 'getFeatures' })).data)
                .toEqual({ access: true });
        });
        await sso.close();
    });

    test('deleting roles removes the luci-sso roles and their rpcd entries', async ({ page, browser }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        for (const name of ['e2e_viewer', 'e2e_none', 'e2e_ro']) {
            await row(page, name).locator('.cbi-button-remove').click();
            await expect(row(page, name)).toHaveCount(0);
        }
        await saveAndApply(page);

        const roles = await listRoles(page);
        expect(Object.keys(roles).filter(n => n.startsWith('e2e_'))).toEqual([]);
        await expect.poll(async () => (await roleOrder(page)).filter(n => n.startsWith('e2e_')), { timeout: 10000 }).toEqual([]);

        const sso = await browser.newPage();
        await loginViaSSO(sso);
        expect((await ubus(sso, 'uci', 'set', { config: 'system', section: '@system[0]', values: { zonename: 'UTC' } })).status).toBe(0);
        await sso.close();
    });
});
