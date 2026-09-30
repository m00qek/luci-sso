'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot, gotoSSOSettings, openTab, modal, fillList, ubus } = require('./helpers');

// The settings page's layout: tabs and field order, the Roles section's
// names, the access-group suggestions, the inline warnings, the Redirect URI
// copy button and the Add box's name check. Nothing here is saved: every
// change is staged in the browser only, or reverted.

function fieldOrder(page, tab) {
    return page.locator(`div[data-tab="${tab}"] .cbi-value`).evaluateAll(
        els => els.map(e => e.getAttribute('data-name')));
}

function warning(page, key) {
    return page.locator(`.luci-sso-warning[data-warning="${key}"]`);
}

// Stages a role with the given rules in the page only (the role editor's own
// Save, not the page's).
async function stageRole(page, name, lists) {
    await page.locator('.cbi-section-create-name').pressSequentially(name);
    await page.locator('.cbi-section-create .cbi-button-add').click();
    await expect(modal(page)).toBeVisible();
    for (const [list, values] of Object.entries(lists))
        await fillList(modal(page), list, values);
    await modal(page).locator('button.cbi-button-positive').click();
    await expect(modal(page)).toBeHidden();
}

async function revert(page) {
    await ubus(page, 'uci', 'revert', { config: 'luci-sso' });
}

test.describe('SSO settings: layout', () => {
    test('the page is "Single Sign-On", with an Identity provider section in two tabs, in setup order', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await expect(page.locator('.cbi-map > h2')).toHaveText('Single Sign-On');
        await expect(page.locator('.cbi-section h3', { hasText: /^Identity provider$/ })).toBeVisible();
        await expect(page.locator('.cbi-tabmenu li')).toHaveText(['Provider', 'Advanced']);

        expect(await fieldOrder(page, 'provider')).toEqual(
            ['issuer_url', 'client_id', 'client_secret', 'redirect_uri', 'scope', '_test_connection', 'enabled']);
        expect(await fieldOrder(page, 'advanced')).toEqual(
            ['require_email_verified', 'clock_tolerance', 'internal_issuer_url']);

        await expect(page.locator('div[data-tab="provider"]')).toHaveAttribute('data-tab-active', 'true');
        await expect(page.locator('div[data-tab="advanced"]')).toHaveAttribute('data-tab-active', 'false');
        await openTab(page, 'advanced');
        await expect(page.locator('div[data-tab="advanced"]')).toHaveAttribute('data-tab-active', 'true');
    });

    test('the Roles section says who can log in and the one save rule', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        const section = page.locator('#cbi-luci-sso-role');
        await expect(section.locator('h3')).toHaveText('Roles');
        await expect(section.locator('.cbi-section-descr')).toContainText(
            'Who can log in, and what they can do. A user gets the first role, from the top, that matches; drag rows to reorder.');
        await expect(section.locator('.cbi-section-descr')).toContainText('Changes take effect with Save & Apply.');
    });

    test('the table shows read * as Everything, write * as Full admin, and an em dash for an empty list', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        const admin = page.locator('.cbi-section-table-row[data-sid="admin"]');
        await expect(admin.locator('td[data-name="_read"]')).toHaveText('Everything');
        await expect(admin.locator('td[data-name="_write"]')).toHaveText('Full admin');
        await expect(admin.locator('td[data-name="_groups"]')).toHaveText('—');
        await expect(admin.locator('td[data-name="_subs"]')).toHaveText('—');
    });

    test("read and write access suggest the router's access groups, and still take any pattern", async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        const groups = (await ubus(page, 'luci-sso', 'list_acl_groups', {})).data.groups;
        expect(groups).toContain('luci-base');

        await page.locator('.cbi-section-table-row[data-sid="admin"] .cbi-button-edit').click();
        await expect(modal(page)).toBeVisible();
        for (const list of ['read', 'write']) {
            const field = modal(page).locator(`[data-name="${list}"]`);
            await field.locator('.cbi-dropdown').click();
            const offered = await field.locator('li[data-value]').evaluateAll(
                els => els.map(e => e.getAttribute('data-value')));
            expect(offered).toContain('*');
            expect(offered).toContain('luci-base');
            expect(offered).toContain('luci-mod-status-realtime');
            expect(offered).not.toContain('unauthenticated');
            await page.keyboard.press('Escape');
        }
        await fillList(modal(page), 'read', ['luci-mod-status-*']);
        await expect(modal(page).locator('[data-name="read"] .item', { hasText: 'luci-mod-status-*' })).toBeAttached();
        await modal(page).locator('button', { hasText: 'Dismiss' }).click();
    });

    test('Scopes warns when a role matches by group and the scopes do not ask for groups', async ({ page }) => {
        await loginAsRoot(page);
        try {
            await gotoSSOSettings(page);
            await expect(warning(page, 'scope')).toBeHidden();

            await stageRole(page, 'e2e_grp', { group: ['staff'] });
            await expect(warning(page, 'scope')).toBeVisible();
            await expect(warning(page, 'scope')).toContainText('Roles e2e_grp match by group, but Scopes does not ask for groups.');

            await page.locator('[id="widget.cbid.luci-sso.default.scope"]').fill('openid profile email groups');
            await page.keyboard.press('Tab');
            await expect(warning(page, 'scope')).toBeHidden();
        } finally {
            await revert(page);
        }
    });

    test('Require Verified Email warns about roles that match by email only', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        await openTab(page, 'advanced');
        // The devenv's admin role matches admin@example.com only.
        await expect(warning(page, 'verified')).toBeVisible();
        await expect(warning(page, 'verified')).toContainText('Roles admin match by email only.');
        await expect(warning(page, 'verified')).toContainText('email_verified: true');

        const flag = page.locator('[id="cbid.luci-sso.default.require_email_verified"] input[type="checkbox"]');
        await flag.uncheck();
        await expect(warning(page, 'verified')).toBeHidden();
        await flag.check();
        await expect(warning(page, 'verified')).toBeVisible();
    });

    test('the Redirect URI is shown in full, with a keyboard-accessible Copy button', async ({ page, context }) => {
        await context.grantPermissions(['clipboard-read', 'clipboard-write']);
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        const input = page.locator('[id="widget.cbid.luci-sso.default.redirect_uri"]');
        const value = await input.inputValue();
        const fits = await input.evaluate(el => el.scrollWidth <= el.clientWidth);
        expect(fits).toBe(true);
        await expect(page.locator('.cbi-value[data-name="redirect_uri"]')).toContainText('Register this exact address with your identity provider.');

        const copy = page.locator('.luci-sso-copy');
        await copy.focus();
        await page.keyboard.press('Enter');
        await expect(page.locator('.luci-sso-copy-status')).toHaveText('Copied');
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(value);
    });

    test('the Add box has a placeholder and explains a name it refuses', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        const box = page.locator('.cbi-section-create-name');
        const add = page.locator('.cbi-section-create .cbi-button-add');
        const why = page.locator('.luci-sso-name-error');
        await expect(box).toHaveAttribute('placeholder', 'New role name, e.g. viewers');

        const cases = [
            ['has space', 'Use only letters, digits and underscores.'],
            ['a'.repeat(33), 'Use at most 32 characters.'],
            ['default', '"default" is reserved for the identity provider settings.'],
            ['admin', 'There is already a role with this name.'],
        ];
        for (const [name, reason] of cases) {
            await box.fill('');
            await box.pressSequentially(name);
            await expect(why).toHaveText(reason);
            await expect(add).toBeDisabled();
        }
        await box.fill('');
        await box.pressSequentially('viewers_2');
        await expect(why).toHaveText('');
        await expect(add).toBeEnabled();
    });
});
