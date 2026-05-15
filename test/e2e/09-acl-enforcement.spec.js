'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot } = require('./helpers');

// Simulates a session where the luci-sso UCI config is not readable by intercepting
// the real ubus endpoint (/ubus/) and returning UBUS_STATUS_ACCESS_DENIED (6) for
// any uci.get call for the luci-sso config.
//
// Why /ubus/ and not /admin/ubus/:
//   LuCI views call rpcd directly via the /ubus/ JSON-RPC endpoint. The /admin/ubus/
//   path is a separate LuCI-proxied route used by the apply/commit flow (08-sso-crud).
//   Intercepting /ubus/ is therefore the correct point to simulate rpcd ACL denial.
//
// Note: LuCI's navigation menu is filtered server-side (dispatcher.uc) before the
// HTML is sent, so server-side ACL enforcement cannot be tested here.
function withSsoAccessDenied(page) {
    return page.route(/\/ubus\//, async (route) => {
        let reqBody;
        try { reqBody = route.request().postDataJSON(); }
        catch { return route.continue(); }
        if (!reqBody) return route.continue();

        const isBatch = Array.isArray(reqBody);
        const requests = isBatch ? reqBody : [reqBody];

        const hasSsoRead = requests.some(req => {
            const [, obj, method, params] = req.params || [];
            return obj === 'uci' && method === 'get' && params?.config === 'luci-sso';
        });
        if (!hasSsoRead) return route.continue();

        const results = requests.map(req => {
            const [, obj, method, params] = req.params || [];
            if (obj === 'uci' && method === 'get' && params?.config === 'luci-sso') {
                return { jsonrpc: '2.0', id: req.id, result: [6] };
            }
            return { jsonrpc: '2.0', id: req.id, result: [0, {}] };
        });

        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(isBatch ? results : results[0])
        });
    });
}

test.describe('Security: Management UI ACLs', () => {

    test.beforeEach(async ({ context }) => {
        await context.clearCookies();
    });

    test('ACL: Direct access to SSO view is rejected when access is denied', async ({ page }) => {
        await withSsoAccessDenied(page);
        await loginAsRoot(page);

        await page.goto('/cgi-bin/luci/admin/services/sso');
        await page.waitForLoadState('networkidle');

        // LuCI shell is present but the form must not render.
        await expect(page.locator('#view')).toBeVisible({ timeout: 5000 });
        await expect(page.locator('.cbi-map')).not.toBeVisible({ timeout: 3000 });
        // LuCI renders a danger notification when uci.load() is rejected.
        await expect(page.locator('.alert-message.danger')).toBeVisible({ timeout: 3000 });
    });

    test('ACL: Access is allowed for authorized sessions', async ({ page }) => {
        await loginAsRoot(page);
        await page.goto('/cgi-bin/luci/admin/services/sso');
        await expect(page.locator('.cbi-map-descr:has-text("Configure OpenID Connect")')).toBeVisible();
    });

});
