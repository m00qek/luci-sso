'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot, gotoSSOSettings, ubus, listRoles, modal, fillList, saveAndApply, RELOAD_WAIT_MS } = require('./helpers');

// Matching a role by the OIDC `sub` claim, against the real CGI and rpcd.
//
// The mock IdP signs everyone in as sub 1234567890, email admin@example.com.
// The devenv's `admin` role matches that email. To log in by sub alone, the
// tests below point the role's email elsewhere and give it the sub, through
// UCI as root, and put the role back afterwards.
//
// Sub rules count only while sub_issuer, the issuer they were made for, is
// issuer_url (OIDC Core §5.7: a sub is unique only within its issuer).

const MOCK_SUB = '1234567890';
const OLD_ISSUER = 'https://old-idp.example.com';

// Sets options of a luci-sso section through UCI, as root, and applies them.
// The CGI reads UCI on every request, so they are in force at once. `null`
// removes an option.
async function setRules(browser, section, values) {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
        await loginAsRoot(page);
        for (const [option, value] of Object.entries(values)) {
            if (value === null)
                await ubus(page, 'uci', 'delete', { config: 'luci-sso', section, option });
            else
                await ubus(page, 'uci', 'set', { config: 'luci-sso', section, values: { [option]: value } });
        }
        // 5 (UBUS_STATUS_NO_DATA): nothing changed, so nothing to apply.
        const r = await ubus(page, 'uci', 'apply', { rollback: false });
        expect([0, 5]).toContain(r.status);
    } finally {
        await context.close();
    }
}

const setAdminRules = (browser, values) => setRules(browser, 'admin', values);

// Binds the sub rules to issuer_url, as `uci set luci-sso.default.sub_issuer=<issuer>` does.
async function bindSubRules(browser) {
    const context = await browser.newContext();
    const page = await context.newPage();
    let issuer;
    try {
        await loginAsRoot(page);
        issuer = await oidcOption(page, 'issuer_url');
    } finally {
        await context.close();
    }
    await setRules(browser, 'default', { sub_issuer: issuer });
}

// An option of the OIDC section, as the page's session sees it: with the
// changes it has staged.
async function oidcOption(page, option) {
    const r = await ubus(page, 'uci', 'get', { config: 'luci-sso', section: 'default', option });
    return r.status === 0 ? r.data.value : null;
}

function subWarnings(page) {
    return page.locator('[data-warning="sub-issuer"]');
}

async function ssoLogin(page) {
    await page.context().clearCookies();
    await page.goto('/');
    await page.locator('#luci-sso-login-btn').click();
}

async function cleanup(browser) {
    await setAdminRules(browser, { email: ['admin@example.com'], sub: null });
    await setRules(browser, 'default', { sub_issuer: null });
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

    test('the role editor has a Subjects list, saved to UCI and shown in the table', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await page.locator('.cbi-section-create-name').pressSequentially('e2e_sub');
        await page.locator('.cbi-section-create .cbi-button-add').click();
        await expect(modal(page)).toBeVisible();

        await expect(modal(page).locator('[data-name="sub"]')).toContainText('Compared exactly, including letter case');
        await fillList(modal(page), 'sub', ['AbC-123', 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6']);
        await modal(page).locator('button.cbi-button-positive').click();
        await expect(modal(page)).toBeHidden();

        const row = page.locator('.cbi-section-table-row[data-sid="e2e_sub"]');
        await expect(row.locator('td[data-name="_subs"]')).toHaveText('AbC-123, f81d4fae-7dec-11d0-a765-00a0c91e6bf6');

        await saveAndApply(page);

        await expect.poll(async () => {
            const r = await ubus(page, 'uci', 'get', { config: 'luci-sso', section: 'e2e_sub', option: 'sub' });
            return r.data && r.data.value;
        }, { timeout: 15000 }).toEqual(['AbC-123', 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6']);
        // The first save with subject rules binds them to the Issuer URL.
        const issuer = await oidcOption(page, 'issuer_url');
        expect(issuer).toMatch(/^https:\/\//);
        expect(await oidcOption(page, 'sub_issuer')).toBe(issuer);
        await expect(subWarnings(page).filter({ visible: true })).toHaveCount(0);
    });

    test('a user whose email matches no role logs in through a role that lists their sub', async ({ page, browser }) => {
        await setAdminRules(browser, { email: ['nobody@example.com'], sub: [MOCK_SUB] });
        await bindSubRules(browser);
        await ssoLogin(page);
        await expect(page.locator('a[href*="/logout"]')).toBeVisible({ timeout: 10000 });
        const cookies = await page.context().cookies();
        expect(cookies.find(c => c.name.startsWith('sysauth'))).toBeDefined();
    });

    test('a sub rule made for another issuer is ignored: the user it would let in is refused', async ({ page, browser }) => {
        await setAdminRules(browser, { email: ['nobody@example.com'], sub: [MOCK_SUB] });
        await setRules(browser, 'default', { sub_issuer: OLD_ISSUER });
        await ssoLogin(page);
        await expect(page.locator('body')).toContainText('Your account is not allowed to manage this router.');
        await expect(page.locator('code')).toHaveText(MOCK_SUB);
    });

    test('the settings page warns when subject rules belong to another issuer, and the button moves them', async ({ page, browser }) => {
        await setAdminRules(browser, { sub: [MOCK_SUB] });
        await setRules(browser, 'default', { sub_issuer: OLD_ISSUER });
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        const issuer = await oidcOption(page, 'issuer_url');
        expect(await oidcOption(page, 'sub_issuer')).toBe(OLD_ISSUER);

        // On the Provider tab, under Issuer URL, and above the Roles table.
        const warnings = subWarnings(page);
        await expect(warnings).toHaveCount(2);
        for (const w of await warnings.all()) {
            await expect(w).toBeVisible();
            await expect(w).toContainText(`Subject rules belong to ${OLD_ISSUER} and are ignored for ${issuer}.`);
            await expect(w).toContainText('A subject identifies one account only at its own provider.');
            await expect(w.locator('button.luci-sso-rebind')).toHaveText('Use these subject rules with the new provider');
        }

        await warnings.first().locator('button.luci-sso-rebind').click();
        for (const w of await warnings.all())
            await expect(w).toHaveText(`Subject rules will be used with ${issuer} after Save & Apply.`);
        expect(await oidcOption(page, 'sub_issuer')).toBe(OLD_ISSUER);

        await saveAndApply(page, { access: false });
        await expect.poll(() => oidcOption(page, 'sub_issuer'), { timeout: 15000 }).toBe(issuer);
        await expect(subWarnings(page).filter({ visible: true })).toHaveCount(0);
    });

    test('editing the Issuer URL warns at once, and a save keeps the subject rules on the old issuer', async ({ page, browser }) => {
        await setAdminRules(browser, { sub: [MOCK_SUB] });
        await bindSubRules(browser);
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        const issuer = await oidcOption(page, 'issuer_url');
        const next = 'https://new-idp.example.com';
        await expect(subWarnings(page).filter({ visible: true })).toHaveCount(0);

        await page.locator('[id="widget.cbid.luci-sso.default.issuer_url"]').fill(next);
        await page.locator('[id="widget.cbid.luci-sso.default.issuer_url"]').press('Tab');
        for (const w of await subWarnings(page).all())
            await expect(w).toContainText(`Subject rules belong to ${issuer} and are ignored for ${next}.`);

        try {
            await page.locator('.cbi-page-actions .cbi-button-save').click();
            await expect.poll(() => oidcOption(page, 'issuer_url'), { timeout: 10000 }).toBe(next);
            expect(await oidcOption(page, 'sub_issuer')).toBe(issuer);
            await expect(subWarnings(page).first()).toContainText(`Subject rules belong to ${issuer} and are ignored for ${next}.`);
        } finally {
            // Staged in this session only, which no other test uses, and set
            // back here: the devenv's IdP stays the issuer. (The session may
            // not call uci revert; LuCI reverts through its own endpoint.)
            await ubus(page, 'uci', 'set', { config: 'luci-sso', section: 'default', values: { issuer_url: issuer } });
        }
        expect(await oidcOption(page, 'issuer_url')).toBe(issuer);
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
