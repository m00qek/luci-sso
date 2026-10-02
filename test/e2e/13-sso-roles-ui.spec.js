'use strict';
const { test, expect } = require('@playwright/test');
const { uciOption, loginAsRoot, gotoSSOSettings, loginViaSSO, ubus, settle, applyAsRoot, modal, fillList, saveAndApply, RELOAD_WAIT_MS } = require('./helpers');

// The Roles section of the SSO settings page against the real rpcd: each
// role's matching rules and place in the order are a `role` section of
// /etc/config/luci-sso, and its read and write lists its rpcd login entry,
// luci_sso_<role> in /etc/config/rpcd; the page stages both, and an apply
// commits both. Every role created here is named e2e_*; the devenv's `admin`
// role is left as it is.
//
// The mock IdP always signs in admin@example.com, which the devenv's `admin`
// role matches. A role created here that matches the same email decides the
// SSO session's rights once it is moved above `admin`: the first match wins.

const READONLY_READ = ['luci-base', 'luci-mod-status-*', 'luci-mod-network-*'];

function row(page, sid) {
    return page.locator(`.cbi-section-table-row[data-sid="${sid}"]`);
}

async function addRole(page, name, { emails = [], read = [], write = [] }) {
    await page.locator('.cbi-section-create-name').pressSequentially(name);
    await page.locator('.cbi-section-create .cbi-button-add').click();
    await expect(modal(page)).toBeVisible();
    await fillList(modal(page), 'email', emails);
    await fillList(modal(page), 'read', read);
    await fillList(modal(page), 'write', write);
    await modal(page).locator('button.cbi-button-positive').click();
    await expect(modal(page)).toBeHidden();
}

// The committed role order in /etc/config/luci-sso.
async function roleOrder(page) {
    const r = await ubus(page, 'uci', 'get', { config: 'luci-sso', type: 'role' });
    return Object.values(r.data.values).sort((a, b) => a['.index'] - b['.index']).map(s => s['.name']);
}

// The option of a role's rpcd login entry, as the page's session sees it.
function entryOption(page, role, option) {
    return uciOption(page, `luci_sso_${role}`, option, 'rpcd');
}

async function cleanup(browser) {
    const context = await browser.newContext();
    const page = await context.newPage();
    let roles = [], entries = [];
    try {
        await loginAsRoot(page);
        const r = await ubus(page, 'uci', 'get', { config: 'luci-sso', type: 'role' });
        roles = Object.keys(r.data?.values ?? {}).filter(n => n.startsWith('e2e_'));
        const e = await ubus(page, 'uci', 'get', { config: 'rpcd', type: 'login' });
        entries = Object.keys(e.data?.values ?? {}).filter(n => n.startsWith('luci_sso_e2e_'));
    } finally {
        await context.close();
    }
    if (roles.length || entries.length) {
        await applyAsRoot(browser, Object.fromEntries(roles.map(n => [n, null])), Object.fromEntries(entries.map(n => [n, null])));
        const page2 = await browser.newPage();
        await settle(page2);
        await page2.close();
    }
}

test.describe.configure({ mode: 'serial', timeout: RELOAD_WAIT_MS + 30000 });

test.describe('SSO settings: roles and their permissions', () => {
    test.beforeAll(async ({ browser }) => { test.setTimeout(RELOAD_WAIT_MS + 30000); await cleanup(browser); });
    test.afterAll(async ({ browser }) => { test.setTimeout(RELOAD_WAIT_MS + 30000); await cleanup(browser); });

    test('creating a role stores its rules in luci-sso and its lists in its rpcd login entry, with unauthenticated', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await page.locator('.cbi-section-create-name').pressSequentially('e2e_viewer');
        await page.locator('.cbi-section-create .cbi-button-add').click();
        await expect(modal(page).locator('[data-name="read"]')).toContainText('unauthenticated is always included');
        await expect(modal(page).locator('.luci-sso-access-note')).toHaveCount(0);
        await fillList(modal(page), 'email', ['viewer@example.com']);
        await fillList(modal(page), 'read', ['luci-mod-status-*']);
        await modal(page).locator('button.cbi-button-positive').click();
        await expect(modal(page)).toBeHidden();

        await expect(row(page, 'e2e_viewer').locator('td[data-name="_read"]')).toHaveText('luci-mod-status-*');
        await saveAndApply(page);

        await expect.poll(async () => (await roleOrder(page)).includes('e2e_viewer'), { timeout: 10000 }).toBe(true);
        expect(await uciOption(page, 'e2e_viewer', 'email')).toEqual(['viewer@example.com']);
        expect(await uciOption(page, 'e2e_viewer', 'read')).toBeNull();
        expect(await entryOption(page, 'e2e_viewer', 'username')).toBe('sso:e2e_viewer');
        expect(await entryOption(page, 'e2e_viewer', 'read')).toEqual(['luci-mod-status-*', 'unauthenticated']);
        expect(await entryOption(page, 'e2e_viewer', 'write')).toBeNull();
        expect(await entryOption(page, 'e2e_viewer', 'password')).toBeNull();
    });

    test('the table and the editor never show unauthenticated, and the entry always keeps it', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        await expect(row(page, 'e2e_viewer').locator('td[data-name="_read"]')).toHaveText('luci-mod-status-*');

        await row(page, 'e2e_viewer').locator('.cbi-button-edit').click();
        await expect(modal(page)).toBeVisible();
        await expect(modal(page).locator('[data-name="read"] .item')).toHaveText(['luci-mod-status-*']);
        await fillList(modal(page), 'read', ['luci-base']);
        await fillList(modal(page), 'write', ['luci-mod-system-config']);
        await modal(page).locator('button.cbi-button-positive').click();
        await expect(modal(page)).toBeHidden();
        await expect(row(page, 'e2e_viewer').locator('td[data-name="_read"]')).toHaveText('luci-mod-status-*, luci-base');
        await saveAndApply(page);

        expect(await entryOption(page, 'e2e_viewer', 'read')).toEqual(['luci-mod-status-*', 'luci-base', 'unauthenticated']);
        expect(await entryOption(page, 'e2e_viewer', 'write')).toEqual(['luci-mod-system-config']);
    });

    test('the editor refuses a read entry that denies unauthenticated, which would leave the role without an entry', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        await row(page, 'e2e_viewer').locator('.cbi-button-edit').click();
        await expect(modal(page)).toBeVisible();
        const field = modal(page).locator('[data-name="read"]');
        await field.locator('.cbi-dropdown').click();
        const custom = field.locator('input.create-item-input:visible');
        await custom.pressSequentially('!unauth*');
        await custom.press('Enter');
        await expect(field.locator('.item', { hasText: '!unauth*' })).toHaveCount(0);
        await page.keyboard.press('Escape');
        await modal(page).locator('button', { hasText: 'Dismiss' }).click();
    });

    test('a role with no access groups gets an entry that grants unauthenticated only, and the page says it grants nothing', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await addRole(page, 'e2e_none', { emails: ['nobody@example.com'] });
        await expect(row(page, 'e2e_none').locator('td[data-name="_read"]')).toHaveText('None: this role grants no access');
        await saveAndApply(page);

        expect(await entryOption(page, 'e2e_none', 'read')).toEqual(['unauthenticated']);
        expect(await entryOption(page, 'e2e_none', 'write')).toBeNull();
        await expect(row(page, 'e2e_none').locator('td[data-name="_read"]')).toHaveText('None: this role grants no access');
    });

    test('the first matching role wins, and dragging a role above another changes which one', async ({ page, browser }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        // A read-only role for the same user as `admin`, added below it.
        await addRole(page, 'e2e_ro', { emails: ['admin@example.com'], read: READONLY_READ });
        await saveAndApply(page);
        expect(await entryOption(page, 'e2e_ro', 'read')).toEqual([...READONLY_READ, 'unauthenticated']);
        await settle(page);

        const sso = await browser.newPage();
        await test.step('below admin: the SSO user gets admin and may save', async () => {
            await loginViaSSO(sso);
            expect((await ubus(sso, 'uci', 'set', { config: 'system', section: '@system[0]', values: { zonename: 'UTC' } })).status).toBe(0);
        });

        await test.step('drag e2e_ro above admin and apply', async () => {
            await gotoSSOSettings(page);
            await row(page, 'e2e_ro').locator('.drag-handle').dragTo(row(page, 'admin'));
            await saveAndApply(page);
            await expect.poll(async () => {
                const order = await roleOrder(page);
                return order.indexOf('e2e_ro') < order.indexOf('admin');
            }, { timeout: 10000 }).toBe(true);
            await settle(page);
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

    test('deleting roles removes them and their rpcd entries, and the user they matched is back on admin', async ({ page, browser }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        for (const name of ['e2e_viewer', 'e2e_none', 'e2e_ro']) {
            await row(page, name).locator('.cbi-button-remove').click();
            await expect(row(page, name)).toHaveCount(0);
        }
        await saveAndApply(page);
        await expect.poll(async () => (await roleOrder(page)).filter(n => n.startsWith('e2e_')), { timeout: 10000 }).toEqual([]);
        for (const name of ['e2e_viewer', 'e2e_none', 'e2e_ro'])
            expect(await entryOption(page, name, 'username')).toBeNull();
        await settle(page);

        const sso = await browser.newPage();
        await loginViaSSO(sso);
        expect((await ubus(sso, 'uci', 'set', { config: 'system', section: '@system[0]', values: { zonename: 'UTC' } })).status).toBe(0);
        await sso.close();
    });
});
