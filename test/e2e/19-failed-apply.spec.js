'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot, gotoSSOSettings, ubus, listRoles, modal, fillList, RELOAD_WAIT_MS } = require('./helpers');

// Save & Apply with UCI changes pending: LuCI applies them, fires
// `uci-applied`, and then arms its own timer to reload the page after
// L.env.apply_display seconds. The page writes the permissions after the
// event. When rpcd refuses them, the page says so and keeps the edits, and
// LuCI's timer must not reload it later and throw them away.
//
// The refusal is real: a read list that denies `unauthenticated`, which
// set_role refuses with INVALID_LIST. The page's clock is Playwright's, so
// the wait past LuCI's timer takes no real time.

const ROLE = 'e2e_fail';

function row(page) {
    return page.locator(`.cbi-section-table-row[data-sid="${ROLE}"]`);
}

async function cleanup(browser) {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
        await loginAsRoot(page);
        await ubus(page, 'uci', 'delete', { config: 'luci-sso', section: ROLE });
        await ubus(page, 'uci', 'apply', { rollback: false });
        if ((await listRoles(page))[ROLE])
            await ubus(page, 'luci-sso', 'delete_role', { name: ROLE });
        await listRoles(page);
    } finally {
        await context.close();
    }
}

test.describe.configure({ mode: 'serial', timeout: RELOAD_WAIT_MS + 90000 });

test.describe('SSO settings: a failed permission write on Save & Apply', () => {
    test.beforeAll(async ({ browser }) => { test.setTimeout(RELOAD_WAIT_MS + 30000); await cleanup(browser); });
    test.afterAll(async ({ browser }) => { test.setTimeout(RELOAD_WAIT_MS + 30000); await cleanup(browser); });

    test('keeps the edits on the page, and no reload comes, long after LuCI\'s apply', async ({ page }) => {
        await loginAsRoot(page);
        await page.clock.install();
        await gotoSSOSettings(page);

        // A new role is a UCI change (its section and email, staged by the
        // editor's Save) and a permission edit, which rpcd will refuse.
        await page.locator('.cbi-section-create-name').pressSequentially(ROLE);
        await page.locator('.cbi-section-create .cbi-button-add').click();
        await expect(modal(page)).toBeVisible();
        await fillList(modal(page), 'email', ['fail@example.com']);
        await fillList(modal(page), 'read', ['!unauthenticated']);
        await modal(page).locator('button.cbi-button-positive').click();
        await expect(modal(page)).toBeHidden();
        await expect(row(page).locator('td[data-name="_read"]')).toHaveText('!unauthenticated');

        let loads = 0;
        page.on('load', () => { loads++; });
        await page.locator('.cbi-page-actions .cbi-button-apply').first().click();

        const refused = page.locator('.alert-message', { hasText: 'Role permissions not saved' });
        await expect(refused).toBeVisible({ timeout: 60000 });
        await expect(refused).toContainText(`Role "${ROLE}": read must not deny 'unauthenticated'`);
        await page.evaluate(() => { window.__e2eNotReloaded = true; });

        // LuCI's own reload was due 105 s after the apply before the fix.
        await page.clock.fastForward('05:00');
        await page.waitForTimeout(1000);

        expect(loads).toBe(0);
        expect(await page.evaluate(() => window.__e2eNotReloaded === true)).toBe(true);
        await expect(refused).toBeVisible();

        // The UCI changes were applied; the permissions were not written.
        const email = await ubus(page, 'uci', 'get', { config: 'luci-sso', section: ROLE, option: 'email' });
        expect(email.data.value).toEqual(['fail@example.com']);
        expect((await listRoles(page))[ROLE]).toBeUndefined();

        // Dismiss: the edit is still on the page, to fix and apply again.
        await refused.getByRole('button', { name: 'Dismiss' }).click();
        await expect(row(page).locator('td[data-name="_read"]')).toHaveText('!unauthenticated');
        expect(loads).toBe(0);
    });
});
