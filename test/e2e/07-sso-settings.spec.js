'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot, gotoSSOSettings, openTab } = require('./helpers');

// Calls rpcd over /ubus/ with the page's own (root) LuCI session and returns
// { status, data }. Used to read/stage/commit UCI directly, so a test can
// assert what actually reached the config after a UI Save.
async function ubus(page, obj, method, params) {
    return page.evaluate(async ([o, m, p]) => {
        const r = await fetch('/ubus/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'call', params: [L.env.sessionid, o, m, p] }),
        });
        const j = await r.json();
        if (j.error) return { error: j.error };
        return { status: j.result[0], data: j.result[1] };
    }, [obj, method, params]);
}


test.describe('SSO Settings: Admin Panel', () => {

    test.beforeEach(async ({ context }) => {
        await context.clearCookies();
    });

    test('Navigation: "Single Sign-On" is listed under Services after login', async ({ page }) => {
        await loginAsRoot(page);

        // Hover over the Services nav entry to reveal the submenu (works for both
        // dropdown-style and sidebar-style LuCI navigation)
        await page.locator('a:has-text("Services"), li:has-text("Services")').first().hover();

        await expect(
            page.locator('a[href*="admin/services/sso"], a:has-text("Single Sign-On")')
        ).toBeVisible({ timeout: 5000 });
    });

    test('Page: renders the Identity provider section and the Roles table', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        // Identity provider section, Provider tab
        await expect(page.locator('[id="cbid.luci-sso.default.enabled"]')).toBeVisible();
        await expect(page.locator('[id="cbid.luci-sso.default.issuer_url"]')).toBeVisible();

        // Roles GridSection table
        await expect(page.locator('th:has-text("Emails")')).toBeVisible();
        await expect(page.locator('th:has-text("Read access")')).toBeVisible();
    });

    test('Field: redirect_uri auto-fills with the current hostname as an HTTPS callback URL', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        // LuCI nests the real <input> inside a wrapper div; the widget element has the widget.cbid.* id
        const value = await page.locator('[id="widget.cbid.luci-sso.default.redirect_uri"]').inputValue();
        const hostname = new URL(page.url()).hostname;
        expect(value).toBe(`https://${hostname}/cgi-bin/luci-sso/callback`);
    });

    test('Field: client_secret is masked as a password input', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await expect(
            page.locator('[id="widget.cbid.luci-sso.default.client_secret"]')
        ).toHaveAttribute('type', 'password');
    });

    test('Validation: clock_tolerance rejects values outside 0–3600', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await openTab(page, 'advanced');
        const clockWidget = page.locator('[id="widget.cbid.luci-sso.default.clock_tolerance"]');
        await clockWidget.fill('9999');
        await page.locator('.cbi-button-save').click();

        // LuCI uses its own validator (not native HTML5) — it sets data-invalid on the widget
        // or adds cbi-input-invalid, and may also show an .alert-message notification
        await expect(
            page.locator('[data-invalid], .cbi-input-invalid, .alert-message.danger')
        ).toBeVisible({ timeout: 3000 });
    });

    test('Validation: issuer_url and redirect_uri reject non-HTTPS values', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        const issuerWidget = page.locator('[id="widget.cbid.luci-sso.default.issuer_url"]');
        await issuerWidget.fill('http://insecure.com');
        // LuCI triggers validation on blur or change; clicking elsewhere or hitting Enter helps
        await page.keyboard.press('Tab');

        await expect(
            page.locator('[id="cbid.luci-sso.default.issuer_url"] .cbi-input-invalid')
        ).toBeVisible({ timeout: 3000 });

        const redirectWidget = page.locator('[id="widget.cbid.luci-sso.default.redirect_uri"]');
        await redirectWidget.fill('http://insecure.com/callback');
        await page.keyboard.press('Tab');

        await expect(
            page.locator('[id="cbid.luci-sso.default.redirect_uri"] .cbi-input-invalid')
        ).toBeVisible({ timeout: 3000 });
    });

    test('Roles table: shows Emails, Groups, Subjects, Read access, Write access columns', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        const headers = page.locator('.cbi-section-table-titles th');
        await expect(headers.filter({ hasText: /^Emails$/ })).toBeVisible();
        await expect(headers.filter({ hasText: /^Groups$/ })).toBeVisible();
        await expect(headers.filter({ hasText: /^Subjects$/ })).toBeVisible();
        await expect(headers.filter({ hasText: /^Read access$/ })).toBeVisible();
        await expect(headers.filter({ hasText: /^Write access$/ })).toBeVisible();
        // devenv pre-seeds an 'admin' role with this email
        await expect(page.locator('td:has-text("admin@example.com")')).toBeVisible();
    });

    test('Roles table: Add button opens the role editor with email, group, subject, read, write fields', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await page.locator('.cbi-section-create-name').pressSequentially('testrole');
        await page.locator('.cbi-section-create .cbi-button-add').click();

        const modal = page.locator('.modal, [role="dialog"]');
        await expect(modal).toBeVisible({ timeout: 10000 });
        
        await expect(modal.locator('h4')).toHaveText('Role: testrole');
        for (const label of ['Emails', 'Groups', 'Subjects', 'Read access', 'Write access'])
            await expect(modal.locator('label.cbi-value-title', { hasText: new RegExp(`^${label}$`) })).toBeVisible();
    });

    // A config from before the option existed has no require_email_verified,
    // which the backend reads as on. The form must show it ticked, and a Save
    // must write '1', not '0'.
    test('Field: Require Verified Email is ticked while the option is unset, and saved as 1', async ({ page }) => {
        await loginAsRoot(page);
        const get = async () => (await ubus(page, 'uci', 'get', { config: 'luci-sso', section: 'default', option: 'require_email_verified' })).data?.value;

        await ubus(page, 'uci', 'delete', { config: 'luci-sso', section: 'default', option: 'require_email_verified' });
        await ubus(page, 'uci', 'apply', { rollback: false });
        expect(await get()).toBeFalsy();

        await gotoSSOSettings(page);
        await openTab(page, 'advanced');
        await expect(page.locator('[id="cbid.luci-sso.default.require_email_verified"] input[type="checkbox"]')).toBeChecked();

        await page.locator('.cbi-button-save').click();
        await expect(page.locator('.cbi-button-save')).toBeEnabled({ timeout: 10000 });
        await ubus(page, 'uci', 'apply', { rollback: false });
        await expect.poll(get, { timeout: 10000 }).toBe('1');
    });

    test('Form: Reset reverts unsaved changes', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        const scopeWidget = page.locator('[id="widget.cbid.luci-sso.default.scope"]');
        const original = await scopeWidget.inputValue();

        await scopeWidget.fill('openid');
        await page.locator('.cbi-button-reset').click();

        await expect(scopeWidget).toHaveValue(original);
    });

    // Regression: the suggested Redirect URI (cfgvalue's fallback when UCI has
    // no value) must actually be written on Save. LuCI's form.save() writes a
    // field only when `forcewrite || cfgvalue != formvalue`; here the widget
    // shows the very suggestion cfgvalue returns, so without forcewrite the two
    // are equal and the value is silently never persisted. This drives a real
    // Save through the UI, commits the staged change, and reads it back.
    test('Field: the suggested Redirect URI is persisted to UCI when saved unchanged', async ({ page }) => {
        await loginAsRoot(page);

        // Start from a clean slate: no redirect_uri in UCI, so cfgvalue falls
        // back to the hostname-based suggestion.
        await ubus(page, 'uci', 'delete', { config: 'luci-sso', section: 'default', option: 'redirect_uri' });
        expect((await ubus(page, 'uci', 'apply', { rollback: false })).status).toBe(0);

        await gotoSSOSettings(page);

        const hostname = new URL(page.url()).hostname;
        const suggestion = `https://${hostname}/cgi-bin/luci-sso/callback`;

        // Precondition: the widget shows the suggestion while UCI holds nothing.
        await expect(page.locator('[id="widget.cbid.luci-sso.default.redirect_uri"]')).toHaveValue(suggestion);
        expect((await ubus(page, 'uci', 'get', { config: 'luci-sso', section: 'default', option: 'redirect_uri' })).data)
            .toBeFalsy();

        // Save the form untouched (the field keeps its suggested value), then
        // commit whatever LuCI staged onto the session.
        await page.locator('.cbi-button-save').click();
        await expect(page.locator('.cbi-button-save')).toBeEnabled({ timeout: 10000 });
        // Commit whatever LuCI staged (a no-op with status 5 when nothing was
        // written — which is exactly the bug this test guards against).
        await ubus(page, 'uci', 'apply', { rollback: false });

        // The suggestion must have reached the committed config.
        await expect
            .poll(async () => (await ubus(page, 'uci', 'get', { config: 'luci-sso', section: 'default', option: 'redirect_uri' })).data?.value,
                { timeout: 10000 })
            .toBe(suggestion);
    });

    // A value the admin types must win over the suggestion and reach UCI.
    test('Field: an explicitly typed Redirect URI is persisted to UCI', async ({ page }) => {
        await loginAsRoot(page);

        await ubus(page, 'uci', 'delete', { config: 'luci-sso', section: 'default', option: 'redirect_uri' });
        expect((await ubus(page, 'uci', 'apply', { rollback: false })).status).toBe(0);

        await gotoSSOSettings(page);

        const typed = 'https://sso.example.org/cgi-bin/luci-sso/callback';
        const widget = page.locator('[id="widget.cbid.luci-sso.default.redirect_uri"]');
        await widget.fill(typed);
        await page.keyboard.press('Tab');

        await page.locator('.cbi-button-save').click();
        await expect(page.locator('.cbi-button-save')).toBeEnabled({ timeout: 10000 });
        await ubus(page, 'uci', 'apply', { rollback: false });

        await expect
            .poll(async () => (await ubus(page, 'uci', 'get', { config: 'luci-sso', section: 'default', option: 'redirect_uri' })).data?.value,
                { timeout: 10000 })
            .toBe(typed);
    });

    // Restore the devenv's canonical redirect_uri so the container config stays
    // pristine for the rest of the suite.
    test.afterAll(async ({ browser }) => {
        const ctx = await browser.newContext();
        const page = await ctx.newPage();
        try {
            await loginAsRoot(page);
            const canonical = `https://${new URL(page.url()).hostname}/cgi-bin/luci-sso/callback`;
            await ubus(page, 'uci', 'set', { config: 'luci-sso', section: 'default', values: { redirect_uri: canonical } });
            await ubus(page, 'uci', 'apply', { rollback: false });
        } finally {
            await ctx.close();
        }
    });

});
