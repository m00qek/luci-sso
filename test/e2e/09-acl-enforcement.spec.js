'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot } = require('./helpers');

// Intercepts browser-level ubus calls to simulate a session that lacks luci-sso UCI access.
// Note: LuCI's navigation menu is filtered server-side (dispatcher.uc) before the HTML is sent,
// so menu visibility cannot be tested by intercepting browser-level ubus calls.
function withSsoAccessDenied(page) {
    return page.route(/\/admin\/ubus/, async (route) => {
        let reqBody;
        try { reqBody = route.request().postDataJSON(); }
        catch { return route.continue(); }
        if (!reqBody) return route.continue();

        const isBatch = Array.isArray(reqBody);
        const requests = isBatch ? reqBody : [reqBody];
        let handled = false;
        const results = requests.map(req => {
            const [sid, obj, method, params] = req.params || [];
            if (obj === 'session' && method === 'access') {
                if (params?.object === 'luci-app-sso' || params?.object === 'luci-sso') {
                    handled = true;
                    if (params?.function) return { jsonrpc: '2.0', id: req.id, result: [0, { access: false }] };
                    return { jsonrpc: '2.0', id: req.id, result: [0, { 'access-group': {}, uci: {} }] };
                }
            }
            return null;
        });

        if (!handled) return route.continue();

        const filled = results.map((r, i) =>
            r ?? { jsonrpc: '2.0', id: requests[i].id, result: [0, {}] }
        );
        return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(isBatch ? filled : filled[0])
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

        // The page loads (LuCI shell is present) but the form does not render because
        // the ubus session.access mock returns access=false for the luci-sso config.
        await expect(page.locator('#view')).toBeVisible({ timeout: 5000 });
        await expect(page.locator('.cbi-map-descr:has-text("Configure OpenID Connect")')).not.toBeVisible();
    });

    test('ACL: Access is allowed for authorized sessions', async ({ page }) => {
        await loginAsRoot(page);
        await page.goto('/cgi-bin/luci/admin/services/sso');
        await expect(page.locator('.cbi-map-descr:has-text("Configure OpenID Connect")')).toBeVisible();
    });

});
