'use strict';
const { test, expect } = require('@playwright/test');
const {
    loginAsRoot, gotoSSOSettings, loginViaSSO, ubus, hasAccess, awaitAccess, uciOption, settle, applyAsRoot, entryFor, modal,
    fillList, removeListItem, saveAndApply, applyFromHeader, RELOAD_WAIT_MS,
} = require('./helpers');

// A role's permissions are its rpcd login entry, luci_sso_<role>, which the
// settings page stages like any other UCI change, together with the role's
// rules in /etc/config/luci-sso: Save stages both, Save & Apply applies both
// from the page footer or from LuCI's header "Unsaved Changes" dialog, Revert
// discards both, and a rollback restores both. After an apply the init script
// makes rpcd reload, so open SSO sessions get the new rights too.
//
// The mock IdP signs in admin@example.com, whom the devenv's `admin` role
// matches. Each test edits that role and watches an open SSO session's
// rights; afterAll gives it read '*' and write '*' back.

// The admin entry's options, as the page's session sees them.
function adminEntry(page, option) {
    return uciOption(page, 'luci_sso_admin', option, 'rpcd');
}

function adminRow(page) {
    return page.locator('.cbi-section-table-row[data-sid="admin"]');
}

async function editAdmin(page) {
    await adminRow(page).locator('.cbi-button-edit').click();
    await expect(modal(page)).toBeVisible();
}

async function saveDialog(page) {
    await modal(page).locator('button.cbi-button-positive').click();
    await expect(modal(page)).toBeHidden();
}

// An SSO session, open before the edit, whose rights the test watches.
async function ssoSession(browser) {
    const page = await browser.newPage();
    await loginViaSSO(page);
    return page;
}

// Gives the admin role its devenv rules and permissions back, and waits until
// `sso` (an SSO session, opened here when not given) has them.
async function restoreAdmin(browser, sso) {
    const own = !sso;
    if (own) sso = await ssoSession(browser);
    try {
        await applyAsRoot(browser, { admin: { email: ['admin@example.com'] } }, entryFor('admin', ['*'], ['*']));
        await awaitAccess(sso, 'luci-base', 'write', true);
    } finally {
        if (own) await sso.close();
    }
}

test.describe.configure({ mode: 'serial', timeout: RELOAD_WAIT_MS + 90000 });

test.describe('SSO settings: role permissions are applied like any LuCI setting', () => {
    test.beforeAll(async ({ browser }) => { test.setTimeout(RELOAD_WAIT_MS + 60000); await restoreAdmin(browser); });
    test.afterAll(async ({ browser }) => { test.setTimeout(RELOAD_WAIT_MS + 60000); await restoreAdmin(browser); });

    // The reviewer's case: before, Save & Apply from the header dialog applied
    // the role's new email but never wrote its permissions, so the role kept
    // write '*'.
    test("(a) edits applied from the header's Unsaved Changes dialog are in force", async ({ page, browser }) => {
        const sso = await ssoSession(browser);
        expect(await hasAccess(sso, 'luci-base', 'write')).toBe(true);

        await loginAsRoot(page);
        await gotoSSOSettings(page);
        await editAdmin(page);
        await fillList(modal(page), 'email', ['second@example.com']);
        await removeListItem(modal(page), 'write', '*');
        await saveDialog(page);
        await expect(adminRow(page).locator('td[data-name="_write"]')).toHaveText('—');
        await page.locator('.cbi-page-actions .cbi-button-save').click();
        await expect(page.locator('[data-indicator="uci-changes"]')).toBeVisible({ timeout: 10000 });

        await applyFromHeader(page);

        await awaitAccess(sso, 'luci-base', 'write', false);
        expect(await hasAccess(sso, 'luci-base', 'read')).toBe(true);
        expect(await adminEntry(page, 'write')).toBeNull();
        expect(await adminEntry(page, 'read')).toEqual(['*']);
        expect(await uciOption(page, 'admin', 'email')).toEqual(['admin@example.com', 'second@example.com']);

        const fresh = await ssoSession(browser);
        expect((await ubus(fresh, 'uci', 'set', { config: 'system', section: '@system[0]', values: { zonename: 'UTC' } })).status).toBe('denied');
        await fresh.close();
        await sso.close();
    });

    test('(b) the footer Save & Apply puts them in force', async ({ page, browser }) => {
        const sso = await ssoSession(browser);
        await restoreAdmin(browser, sso);

        await loginAsRoot(page);
        await gotoSSOSettings(page);
        await editAdmin(page);
        await removeListItem(modal(page), 'write', '*');
        await fillList(modal(page), 'write', ['luci-base', 'luci-mod-system-config']);
        await saveDialog(page);
        await expect(adminRow(page).locator('td[data-name="_write"]')).toHaveText('luci-base, luci-mod-system-config');

        await saveAndApply(page);

        await awaitAccess(sso, 'luci-mod-network-config', 'write', false);
        expect(await hasAccess(sso, 'luci-mod-system-config', 'write')).toBe(true);
        expect((await ubus(sso, 'uci', 'set', { config: 'system', section: '@system[0]', values: { zonename: 'UTC' } })).status).toBe(0);
        expect((await ubus(sso, 'uci', 'set', { config: 'network', section: 'loopback', values: { mtu: '1400' } })).status).toBe('denied');
        await sso.close();
    });

    test("(c) Save stages both files' changes without putting them in force; Revert discards both", async ({ page, browser }) => {
        const sso = await ssoSession(browser);
        await restoreAdmin(browser, sso);

        await loginAsRoot(page);
        await gotoSSOSettings(page);
        await editAdmin(page);
        await fillList(modal(page), 'email', ['third@example.com']);
        await removeListItem(modal(page), 'write', '*');
        await saveDialog(page);
        await page.locator('.cbi-page-actions .cbi-button-save').click();
        await expect(page.locator('[data-indicator="uci-changes"]')).toBeVisible({ timeout: 10000 });
        expect(await adminEntry(page, 'write')).toBeNull();

        await settle(page);
        expect(await hasAccess(sso, 'luci-base', 'write')).toBe(true);

        await page.locator('[data-indicator="uci-changes"]').click();
        await expect(modal(page).getByText('# /etc/config/luci-sso')).toBeVisible();
        await expect(modal(page).getByText('# /etc/config/rpcd')).toBeVisible();
        await modal(page).locator('.cbi-button-reset', { hasText: 'Revert' }).click();
        await expect(page.getByText('Changes have been reverted.')).toBeVisible({ timeout: 30000 });
        await page.waitForEvent('load', { timeout: 30000 });
        await page.waitForSelector('.cbi-map');

        await expect(adminRow(page).locator('td[data-name="_write"]')).toHaveText('Full admin');
        await expect(page.locator('[data-indicator="uci-changes"]')).toBeHidden();
        expect(await adminEntry(page, 'write')).toEqual(['*']);
        expect(await uciOption(page, 'admin', 'email')).toEqual(['admin@example.com']);
        await settle(page);
        expect(await hasAccess(sso, 'luci-base', 'write')).toBe(true);
        await sso.close();
    });

    test('(e) the page stages changes to luci_sso_* rpcd sections only, never a password', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        for (const name of ['e2e_one', 'e2e_two']) {
            await page.locator('.cbi-section-create-name').pressSequentially(name);
            await page.locator('.cbi-section-create .cbi-button-add').click();
            await expect(modal(page)).toBeVisible();
            await fillList(modal(page), 'email', [`${name}@example.com`]);
            await fillList(modal(page), 'read', ['luci-base']);
            await saveDialog(page);
        }
        await editAdmin(page);
        await fillList(modal(page), 'write', ['luci-base']);
        await saveDialog(page);
        await page.locator('.cbi-section-table-row[data-sid="e2e_two"] .cbi-button-remove').click();
        await page.locator('.cbi-page-actions .cbi-button-save').click();
        await expect(page.locator('[data-indicator="uci-changes"]')).toBeVisible({ timeout: 10000 });

        try {
            const changes = (await ubus(page, 'uci', 'changes', { config: 'rpcd' })).data.changes;
            expect(changes.length).toBeGreaterThan(0);
            for (const c of changes) {
                expect(c[1]).toMatch(/^luci_sso_/);
                expect(c[2]).not.toBe('password');
            }
            expect(await uciOption(page, 'luci_sso_e2e_one', 'username', 'rpcd')).toBe('sso:e2e_one');
            expect(await uciOption(page, 'luci_sso_e2e_one', 'read', 'rpcd')).toEqual(['luci-base', 'unauthenticated']);
            expect(await uciOption(page, 'luci_sso_e2e_two', 'username', 'rpcd')).toBeNull();
        } finally {
            await page.locator('[data-indicator="uci-changes"]').click();
            await modal(page).locator('.cbi-button-reset', { hasText: 'Revert' }).click();
            await expect(page.getByText('Changes have been reverted.')).toBeVisible({ timeout: 30000 });
        }
    });

    test("(f) LuCI's rollback restores both the rules and the permissions", async ({ page, browser }) => {
        const sso = await ssoSession(browser);
        await restoreAdmin(browser, sso);

        // An apply of the root session, never confirmed. The SSO session,
        // another session that may read both files, watches what is
        // committed: rpcd gives the root session its changes back as staged
        // ones after the rollback, so its own view shows them still.
        await loginAsRoot(page);
        await ubus(page, 'uci', 'set', { config: 'luci-sso', section: 'admin', values: { email: ['admin@example.com', 'rollback@example.com'] } });
        await ubus(page, 'uci', 'delete', { config: 'rpcd', section: 'luci_sso_admin', option: 'write' });
        expect((await ubus(page, 'uci', 'apply', { rollback: true, timeout: 5 })).status).toBe(0);

        expect(await uciOption(sso, 'admin', 'email')).toEqual(['admin@example.com', 'rollback@example.com']);
        expect(await uciOption(sso, 'luci_sso_admin', 'write', 'rpcd')).toBeNull();
        expect(await hasAccess(sso, 'luci-base', 'write')).toBe(true);

        // No confirmation: rpcd rolls back after 5 s. (Nobody asks `uci
        // confirm`: the root session's own call would confirm the apply.)
        await expect.poll(() => uciOption(sso, 'admin', 'email'), { timeout: 30000, intervals: [1000] }).toEqual(['admin@example.com']);
        expect(await uciOption(sso, 'luci_sso_admin', 'write', 'rpcd')).toEqual(['*']);
        await settle(sso);
        expect(await hasAccess(sso, 'luci-base', 'write')).toBe(true);

        // The rolled-back changes are the root session's unsaved changes again.
        await gotoSSOSettings(page);
        await page.locator('[data-indicator="uci-changes"]').click();
        await expect(modal(page).getByText('# /etc/config/rpcd')).toBeVisible();
        await modal(page).locator('.cbi-button-reset', { hasText: 'Revert' }).click();
        await expect(page.getByText('Changes have been reverted.')).toBeVisible({ timeout: 30000 });
        await sso.close();
    });
});
