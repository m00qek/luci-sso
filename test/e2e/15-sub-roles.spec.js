'use strict';
const { test, expect } = require('@playwright/test');
const { uciOption, loginAsRoot, gotoSSOSettings, ubus, settle, applyAsRoot, modal, fillList, saveAndApply, RELOAD_WAIT_MS } = require('./helpers');

// Matching a role by the OIDC `sub` claim, against the real CGI and rpcd.
//
// The mock IdP signs everyone in as sub 1234567890, email admin@example.com.
// The devenv's `admin` role matches that email. To log in by sub alone, the
// tests below point the role's email elsewhere and give it the sub, through
// UCI as root, and put the role back afterwards.
//
// A role's sub rules count only while its own sub_issuer, the issuer they
// were made for, is issuer_url (OIDC Core §5.7: a sub is unique only within
// its issuer).

const MOCK_SUB = '1234567890';
const OLD_ISSUER = 'https://old-idp.example.com';

// The devenv's Issuer URL, as the page's session sees it.
async function issuerUrl(page) {
    return uciOption(page, 'default', 'issuer_url');
}

async function devenvIssuer(browser) {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
        await loginAsRoot(page);
        return await issuerUrl(page);
    } finally {
        await context.close();
    }
}

function subWarnings(page) {
    return page.locator('[data-warning="sub-issuer"]');
}

function row(page, sid) {
    return page.locator(`.cbi-section-table-row[data-sid="${sid}"]`);
}

async function ssoLogin(page) {
    await page.context().clearCookies();
    await page.goto('/');
    await page.locator('#luci-sso-login-btn').click();
}

let ISSUER = null;

async function cleanup(browser) {
    await applyAsRoot(browser, {
        admin: { email: ['admin@example.com'], sub: null, sub_issuer: null },
        default: { issuer_url: ISSUER },
        e2e_sub: null,
    }, { luci_sso_e2e_sub: null });
    const page = await browser.newPage();
    await settle(page);
    await page.close();
}

test.describe.configure({ mode: 'serial', timeout: RELOAD_WAIT_MS + 60000 });

test.describe('Roles matched by sub', () => {
    test.beforeAll(async ({ browser }) => {
        test.setTimeout(RELOAD_WAIT_MS + 30000);
        ISSUER = await devenvIssuer(browser);
        expect(ISSUER).toMatch(/^https:\/\//);
        await cleanup(browser);
    });
    test.afterAll(async ({ browser }) => { test.setTimeout(RELOAD_WAIT_MS + 30000); await cleanup(browser); });

    // (d): the dialog's Save stages the subjects and their issuer together,
    // and the apply commits them together.
    test('the role dialog saves the subjects with their issuer, prefilled with the Issuer URL', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await page.locator('.cbi-section-create-name').pressSequentially('e2e_sub');
        await page.locator('.cbi-section-create .cbi-button-add').click();
        await expect(modal(page)).toBeVisible();

        await expect(modal(page).locator('[data-name="sub"]')).toContainText('Compared exactly, including letter case');
        const field = modal(page).locator('[id="widget.cbid.luci-sso.e2e_sub.sub_issuer"]');
        await expect(field).toHaveValue(ISSUER);
        await fillList(modal(page), 'sub', ['AbC-123', 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6']);
        await modal(page).locator('button.cbi-button-positive').click();
        await expect(modal(page)).toBeHidden();

        // Staged in one save: both options are in the session's changes.
        const changes = (await ubus(page, 'uci', 'changes', { config: 'luci-sso' })).data.changes;
        const staged = changes.filter(c => c[1] === 'e2e_sub').map(c => c[2]);
        expect(staged).toContain('sub');
        expect(staged).toContain('sub_issuer');

        await expect(row(page, 'e2e_sub').locator('td[data-name="_subs"]')).toContainText('AbC-123, f81d4fae-7dec-11d0-a765-00a0c91e6bf6');
        await expect(row(page, 'e2e_sub').locator('.luci-sso-sub-ignored')).toBeHidden();

        await saveAndApply(page);

        expect(await uciOption(page, 'e2e_sub', 'sub')).toEqual(['AbC-123', 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6']);
        expect(await uciOption(page, 'e2e_sub', 'sub_issuer')).toBe(ISSUER);
        await expect(subWarnings(page).filter({ visible: true })).toHaveCount(0);
    });

    test('changing the Issuer URL warns about the role and leaves its sub rules on their issuer', async ({ page, browser }) => {
        const next = 'https://new-idp.example.com';
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        await expect(subWarnings(page).filter({ visible: true })).toHaveCount(0);

        try {
            await page.locator('[id="widget.cbid.luci-sso.default.issuer_url"]').fill(next);
            await page.locator('[id="widget.cbid.luci-sso.default.issuer_url"]').press('Tab');
            // Under Issuer URL, and above the Roles table.
            await expect(subWarnings(page)).toHaveCount(2);
            for (const w of await subWarnings(page).all()) {
                await expect(w).toBeVisible();
                await expect(w.locator('.luci-sso-sub-mismatch[data-role="e2e_sub"]'))
                    .toContainText(`The subject rules of role e2e_sub belong to ${ISSUER} and are ignored for ${next}.`);
            }
            await expect(row(page, 'e2e_sub').locator('.luci-sso-sub-ignored')).toHaveText('(ignored: another provider)');

            await saveAndApply(page);
            expect(await issuerUrl(page)).toBe(next);
            expect(await uciOption(page, 'e2e_sub', 'sub_issuer')).toBe(ISSUER);
            await expect(subWarnings(page).first().locator('.luci-sso-sub-mismatch[data-role="e2e_sub"]')).toBeVisible();
            await expect(row(page, 'e2e_sub').locator('.luci-sso-sub-ignored')).toBeVisible();

            // The role's button stages its own sub_issuer only.
            await subWarnings(page).first().locator('button.luci-sso-rebind[data-role="e2e_sub"]').click();
            await expect(subWarnings(page).filter({ visible: true })).toHaveCount(0);
            await expect(row(page, 'e2e_sub').locator('.luci-sso-sub-ignored')).toBeHidden();
            await expect.poll(() => uciOption(page, 'e2e_sub', 'sub_issuer'), { timeout: 10000 }).toBe(next);
            expect(await uciOption(page, 'admin', 'sub_issuer')).toBeNull();
        } finally {
            await applyAsRoot(browser, { default: { issuer_url: ISSUER }, e2e_sub: { sub_issuer: ISSUER } });
        }
    });

    test('a user whose email matches no role logs in through a role that lists their sub', async ({ page, browser }) => {
        await applyAsRoot(browser, { admin: { email: ['nobody@example.com'], sub: [MOCK_SUB], sub_issuer: ISSUER } });
        await settle(page);
        await ssoLogin(page);
        await expect(page.locator('a[href*="/logout"]')).toBeVisible({ timeout: 10000 });
        const cookies = await page.context().cookies();
        expect(cookies.find(c => c.name.startsWith('sysauth'))).toBeDefined();
    });

    test('a sub rule made for another issuer is ignored: the user it would let in is refused', async ({ page, browser }) => {
        await applyAsRoot(browser, { admin: { email: ['nobody@example.com'], sub: [MOCK_SUB], sub_issuer: OLD_ISSUER } });
        await settle(page);
        await ssoLogin(page);
        await expect(page.locator('body')).toContainText('Your account is not allowed to manage this router.');
        await expect(page.locator('code')).toHaveText(MOCK_SUB);
    });

    test('the page warns about that role, and its button moves its rules to this provider', async ({ page, browser }) => {
        await applyAsRoot(browser, { admin: { sub: [MOCK_SUB], sub_issuer: OLD_ISSUER } });
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        const warnings = subWarnings(page);
        await expect(warnings).toHaveCount(2);
        for (const w of await warnings.all()) {
            await expect(w).toBeVisible();
            await expect(w).toContainText(`The subject rules of role admin belong to ${OLD_ISSUER} and are ignored for ${ISSUER}.`);
            await expect(w).toContainText('A subject identifies one account only at its own provider.');
            await expect(w.locator('button.luci-sso-rebind[data-role="admin"]')).toHaveText('Use with this provider');
        }
        await expect(warnings.first().locator('.luci-sso-sub-mismatch')).toHaveCount(1);

        // The button stages the change at once, as a Save would.
        await warnings.first().locator('button.luci-sso-rebind[data-role="admin"]').click();
        await expect(warnings.filter({ visible: true })).toHaveCount(0);
        await expect(page.locator('[data-indicator="uci-changes"]')).toBeVisible({ timeout: 10000 });
        expect(await uciOption(page, 'admin', 'sub_issuer')).toBe(ISSUER);

        await saveAndApply(page);
        await expect.poll(() => uciOption(page, 'admin', 'sub_issuer'), { timeout: 15000 }).toBe(ISSUER);
        await expect(subWarnings(page).filter({ visible: true })).toHaveCount(0);
    });

    test('a user whose sub and email match no role is refused, and sees their own sub on the error page', async ({ page, browser }) => {
        // A sub one character longer than the mock's: a prefix is no match.
        await applyAsRoot(browser, { admin: { email: ['nobody@example.com'], sub: ['1234567890A'], sub_issuer: ISSUER } });
        await settle(page);
        await ssoLogin(page);
        await expect(page.locator('h1')).toHaveText('Single sign-on');
        await expect(page.locator('body')).toContainText('Your account is not allowed to manage this router.');
        await expect(page.locator('body')).toContainText('give your administrator this account identifier');
        await expect(page.locator('code')).toHaveText(MOCK_SUB);
        await expect(page.locator('body')).not.toContainText('admin@example.com');
    });
});
