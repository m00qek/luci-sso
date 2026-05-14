'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot, gotoSSOSettings } = require('./helpers');


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

    test('Page: renders Settings section and Users table', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        // Settings section fields
        await expect(page.locator('[id="cbid.luci-sso.default.enabled"]')).toBeVisible();
        await expect(page.locator('[id="cbid.luci-sso.default.issuer_url"]')).toBeVisible();

        // Users GridSection table
        await expect(page.locator('th:has-text("Emails")')).toBeVisible();
        await expect(page.locator('th:has-text("Read Access")')).toBeVisible();
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

    test('Users table: shows Emails, Groups, Read Access, Write Access columns', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await expect(page.locator('th:has-text("Emails")')).toBeVisible();
        await expect(page.locator('th:has-text("Groups")')).toBeVisible();
        await expect(page.locator('th:has-text("Read Access")')).toBeVisible();
        await expect(page.locator('th:has-text("Write Access")')).toBeVisible();
        // devenv pre-seeds an 'admin' role with this email
        await expect(page.locator('td:has-text("admin@example.com")')).toBeVisible();
    });

    test('Users table: Add button opens modal with email, group, read, write fields', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        await page.locator('.cbi-section-create-name').pressSequentially('testrole');
        await page.locator('.cbi-section-create .cbi-button-add').click();

        const modal = page.locator('.modal, [role="dialog"]');
        await expect(modal).toBeVisible({ timeout: 10000 });
        
        await expect(modal.locator('label:has-text("Email Addresses")')).toBeVisible();
        await expect(modal.locator('label:has-text("Groups")')).toBeVisible();
        await expect(modal.locator('label:has-text("Read Access")')).toBeVisible();
        await expect(modal.locator('label:has-text("Write Access")')).toBeVisible();
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

});
