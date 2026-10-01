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

    // The provider's values reach the page inside the router's messages. They
    // are text: no markup in them may become HTML in the admin's session.
    test('shows a hostile provider\'s issuer as text, and runs none of its markup', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        const saved = await uciGet(page, 'issuer_url');

        // The mock IdP declares `${saved}/<img src=x onerror="window.__xss=1">` there.
        await page.locator('[id="widget.cbid.luci-sso.default.issuer_url"]').fill(saved + '/hostile');
        await testConnection(page);

        await expect(check(page, 'issuer_match')).toHaveAttribute('data-status', 'fail');
        // The router quotes it with "<" and ">" as "?" (a second line of defence).
        await expect(check(page, 'issuer_match')).toContainText(`The provider declares "${saved}/?img src=x onerror="window.__xss=1"?"`);
        await expect(page.locator('.luci-sso-test-output img')).toHaveCount(0);
        expect(await page.evaluate(() => window.__xss)).toBeUndefined();
    });

    test('shows the router\'s messages as text even when they hold markup', async ({ page }) => {
        // The page's own line of defence: a result whose message and check
        // name carry raw markup, as the router never sends them.
        const markup = '<img src=x onerror="window.__xss=1"><b>bold</b>';
        await page.route('**/ubus/**', async (route) => {
            let body;
            try { body = route.request().postDataJSON(); } catch (e) { return route.continue(); }
            const calls = Array.isArray(body) ? body : [body];
            if (!calls.every(c => c && Array.isArray(c.params) && c.params[2] === 'test_connection_result'))
                return route.continue();
            const reply = calls.map(c => ({ jsonrpc: '2.0', id: c.id, result: [0, { done: true, checks: [
                { id: 'issuer_https', status: 'pass', message: markup },
                { id: markup, status: 'fail', message: markup },
            ] }] }));
            await route.fulfill({ contentType: 'application/json', body: JSON.stringify(Array.isArray(body) ? reply : reply[0]) });
        });
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        await testConnection(page);

        await expect(page.locator('.luci-sso-check-message').first()).toHaveText(markup);
        await expect(page.locator('.luci-sso-check-title').nth(1)).toHaveText(markup);
        await expect(page.locator('.luci-sso-test-output img, .luci-sso-test-output b')).toHaveCount(0);
        expect(await page.evaluate(() => window.__xss)).toBeUndefined();
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
