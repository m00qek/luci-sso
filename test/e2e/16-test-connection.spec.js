'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot, gotoSSOSettings, ubus } = require('./helpers');

// The settings page's Test connection button, against the real rpcd plugin
// and the devenv's mock IdP. The button checks the form's values, saved or
// not, and saves nothing.

const CHECKS = ['issuer_https', 'discovery', 'issuer_match', 'endpoints', 'jwks', 'redirect_uri', 'client_credentials'];

function results(page) {
    return page.locator('.luci-sso-test-results');
}

function check(page, id) {
    return results(page).locator(`li[data-check="${id}"]`);
}

async function testConnection(page) {
    await page.locator('#luci-sso-test-connection').click();
    await expect(results(page)).toBeVisible({ timeout: 40000 });
}

async function uciGet(page, option) {
    const r = await ubus(page, 'uci', 'get', { config: 'luci-sso', section: 'default', option });
    return r.data && r.data.value;
}

test.describe.configure({ mode: 'serial', timeout: 90000 });

test.describe('SSO settings: Test connection', () => {
    test('every check passes against the devenv IdP', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        await testConnection(page);

        for (const id of CHECKS)
            await expect(check(page, id), id).toHaveAttribute('data-status', 'pass');
        await expect(page.locator('.luci-sso-test-summary')).toHaveText('All checks passed.');
        await expect(check(page, 'client_credentials')).toContainText('accepted the Client ID and Client Secret');
        // The secret never comes back to the page.
        await expect(page.locator('.luci-sso-test-output')).not.toContainText('secret-key-123');
    });

    test('an unsaved issuer with a trailing slash fails the issuer check with the hint, and nothing is saved', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        const saved = await uciGet(page, 'issuer_url');

        const issuer = page.locator('[id="widget.cbid.luci-sso.default.issuer_url"]');
        await issuer.fill(saved + '/');
        await testConnection(page);

        await expect(check(page, 'discovery')).toHaveAttribute('data-status', 'pass');
        await expect(check(page, 'issuer_match')).toHaveAttribute('data-status', 'fail');
        await expect(check(page, 'issuer_match')).toContainText('They differ only in a trailing slash, letter case or default port');
        await expect(check(page, 'client_credentials')).toHaveAttribute('data-status', 'skip');
        await expect(page.locator('.luci-sso-test-summary')).toContainText('checks failed');

        expect(await uciGet(page, 'issuer_url')).toBe(saved);
        const changes = await ubus(page, 'uci', 'changes', { config: 'luci-sso' });
        expect(changes.data.changes || []).toEqual([]);
    });

    test('an unsaved wrong client secret fails the credentials check', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        await page.locator('[id="widget.cbid.luci-sso.default.client_secret"]').fill('not-the-secret');
        await testConnection(page);
        await expect(check(page, 'client_credentials')).toHaveAttribute('data-status', 'fail');
        await expect(check(page, 'client_credentials')).toContainText('invalid_client');
    });

    test('works while SSO is disabled', async ({ page }) => {
        await loginAsRoot(page);
        try {
            await ubus(page, 'uci', 'set', { config: 'luci-sso', section: 'default', values: { enabled: '0' } });
            await ubus(page, 'uci', 'apply', { rollback: false });
            await gotoSSOSettings(page);
            await testConnection(page);
            for (const id of CHECKS)
                await expect(check(page, id), id).toHaveAttribute('data-status', 'pass');
        } finally {
            await ubus(page, 'uci', 'set', { config: 'luci-sso', section: 'default', values: { enabled: '1' } });
            await ubus(page, 'uci', 'apply', { rollback: false });
        }
    });
});
