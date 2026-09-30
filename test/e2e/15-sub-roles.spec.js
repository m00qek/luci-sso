'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot, gotoSSOSettings, ubus, listRoles, RELOAD_WAIT_MS } = require('./helpers');

// Matching a role by the OIDC `sub` claim, against the real CGI and rpcd.
//
// The mock IdP signs everyone in as sub 1234567890, email admin@example.com.
// The devenv's `admin` role matches that email. To log in by sub alone, the
// tests below point the role's email elsewhere and give it the sub, through
// UCI as root, and put the role back afterwards.

const MOCK_SUB = '1234567890';

function modal(page) {
    return page.locator('#modal_overlay .modal');
}

// Sets the devenv admin role's matching rules through UCI, as root, and
// applies them. The CGI reads UCI on every request, so they are in force at
// once. `null` removes an option.
async function setAdminRules(browser, values) {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
        await loginAsRoot(page);
        for (const [option, value] of Object.entries(values)) {
            if (value === null)
                await ubus(page, 'uci', 'delete', { config: 'luci-sso', section: 'admin', option });
            else
                await ubus(page, 'uci', 'set', { config: 'luci-sso', section: 'admin', values: { [option]: value } });
        }
        const r = await ubus(page, 'uci', 'apply', { rollback: false });
        expect(r.status).toBe(0);
    } finally {
        await context.close();
    }
}

async function ssoLogin(page) {
    await page.context().clearCookies();
    await page.goto('/');
    await page.locator('#luci-sso-login-btn').click();
}

async function cleanup(browser) {
    await setAdminRules(browser, { email: ['admin@example.com'], sub: null });
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
        await loginAsRoot(page);
        await ubus(page, 'uci', 'delete', { config: 'luci-sso', section: 'e2e_sub' });
        await ubus(page, 'uci', 'apply', { rollback: false });
        if ((await listRoles(page)).e2e_sub)
            await ubus(page, 'luci-sso', 'delete_role', { name: 'e2e_sub' });
        await listRoles(page);
    } finally {
        await context.close();
    }
}

test.describe.configure({ mode: 'serial', timeout: RELOAD_WAIT_MS + 60000 });

test.describe('Roles matched by sub', () => {
    test.beforeAll(async ({ browser }) => { test.setTimeout(RELOAD_WAIT_MS + 30000); await cleanup(browser); });
    test.afterAll(async ({ browser }) => { test.setTimeout(RELOAD_WAIT_MS + 30000); await cleanup(browser); });

    test('the role editor has a Subjects (sub) list, saved to UCI and shown in the table', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await page.locator('.cbi-section-create-name').pressSequentially('e2e_sub');
        await page.locator('.cbi-section-create .cbi-button-add').click();
        await expect(modal(page)).toBeVisible();

        const field = modal(page).locator('[data-name="sub"]');
        await expect(field).toContainText('Compared exactly, including letter case');
        for (const v of ['AbC-123', 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6']) {
            await field.locator('input[type="text"]').last().fill(v);
            await field.locator('.cbi-button-add').click();
        }
        await modal(page).locator('button.cbi-button-positive').click();
        await expect(modal(page)).toBeHidden();

        const row = page.locator('.cbi-section-table-row[data-sid="e2e_sub"]');
        await expect(row.locator('td[data-name="_subs"]')).toHaveText('AbC-123, f81d4fae-7dec-11d0-a765-00a0c91e6bf6');

        await page.locator('.cbi-page-actions .cbi-button-apply').first().click();
        await expect(page.getByText('Configuration changes applied.')).toBeVisible({ timeout: RELOAD_WAIT_MS + 30000 });

        await expect.poll(async () => {
            const r = await ubus(page, 'uci', 'get', { config: 'luci-sso', section: 'e2e_sub', option: 'sub' });
            return r.data && r.data.value;
        }, { timeout: 15000 }).toEqual(['AbC-123', 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6']);
    });

    test('a user whose email matches no role logs in through a role that lists their sub', async ({ page, browser }) => {
        await setAdminRules(browser, { email: ['nobody@example.com'], sub: [MOCK_SUB] });
        await ssoLogin(page);
        await expect(page.locator('a[href*="/logout"]')).toBeVisible({ timeout: 10000 });
        const cookies = await page.context().cookies();
        expect(cookies.find(c => c.name.startsWith('sysauth'))).toBeDefined();
    });

    test('a user whose sub and email match no role is refused, and sees their own sub on the error page', async ({ page, browser }) => {
        // A sub one character longer than the mock's: a prefix is no match.
        await setAdminRules(browser, { email: ['nobody@example.com'], sub: ['1234567890A'] });
        await ssoLogin(page);
        await expect(page.locator('h1')).toHaveText('Single sign-on');
        await expect(page.locator('body')).toContainText('Your account is not allowed to manage this router.');
        await expect(page.locator('body')).toContainText('give your administrator this account identifier');
        await expect(page.locator('code')).toHaveText(MOCK_SUB);
        await expect(page.locator('body')).not.toContainText('admin@example.com');
    });
});
