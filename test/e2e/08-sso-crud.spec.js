'use strict';
const { test, expect } = require('@playwright/test');
const { loginAsRoot, gotoSSOSettings } = require('./helpers');

/**
 * Advanced Ubus Mocking for CRUD operations.
 * Intercepts uci.get, uci.add, uci.set, and uci.apply.
 */
function setupPristineMocks(page) {
    const config = {
        default: {
            '.name': 'default', '.type': 'oidc', '.anonymous': false,
            enabled: '1',
            issuer_url: 'https://idp.example.com',
            client_id: 'client-x',
            client_secret: 'secret-y',
            clock_tolerance: '60'
        },
        admin: {
            '.name': 'admin', '.type': 'role', '.anonymous': false,
            email: ['admin@example.com'],
            read: ['*'],
            write: ['*']
        }
    };

    return page.route(/\/admin\/ubus/, async (route) => {
        const reqBody = route.request().postDataJSON();
        const isBatch = Array.isArray(reqBody);
        const requests = isBatch ? reqBody : [reqBody];

        const results = requests.map(req => {
            const [sid, obj, method, params] = req.params || [];

            if (obj === 'uci' && method === 'get' && params?.config === 'luci-sso') {
                return { jsonrpc: '2.0', id: req.id, result: [0, { values: config }] };
            }

            if (obj === 'uci' && (method === 'add' || method === 'set' || method === 'apply' || method === 'commit')) {
                return { jsonrpc: '2.0', id: req.id, result: [0] };
            }

            // Pass through unrecognised calls (auth/session) without route.fetch().
            return null;
        });

        // All unhandled — let the real server respond.
        if (results.every(r => r === null)) return route.continue();

        // Some unhandled slots — return generic success to avoid route.fetch().
        const filled = results.map((r, i) =>
            r ?? { jsonrpc: '2.0', id: requests[i].id, result: [0, {}] }
        );

        await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify(isBatch ? filled : filled[0])
        });
    });
}

test.describe('SSO Settings: Pristine CRUD Lifecycle', () => {

    test.beforeEach(async ({ context }) => {
        await context.clearCookies();
    });

    test('CRUD: Create a new role with multi-item lists and verify table summary', async ({ page }) => {
        await setupPristineMocks(page);
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        // 1. Add a new role
        await page.locator('.cbi-section-create-name').pressSequentially('newrole');
        await page.locator('.cbi-button-add').click();
        const modal = page.locator('.modal, [role="dialog"]');
        await expect(modal).toBeVisible();

        // 2. Add multiple emails
        const emailField = modal.locator('[data-name="email"]');
        // Type first email
        await emailField.locator('input[type="text"]').last().fill('user1@example.com');
        // Click "+" to add another row (LuCI DynamicList behavior)
        await emailField.locator('.cbi-button-add').click();
        await emailField.locator('input[type="text"]').last().fill('user2@example.com');

        // 3. Add a group
        const groupField = modal.locator('[data-name="group"]');
        await groupField.locator('input[type="text"]').last().fill('DevOps');

        // 4. Set Permissions
        const readField = modal.locator('[data-name="read"]');
        await readField.locator('input[type="text"]').last().fill('superuser');

        const writeField = modal.locator('[data-name="write"]');
        await writeField.locator('input[type="text"]').last().fill('superuser');

        // 5. Close modal
        await modal.locator('button.cbi-button-positive').click();
        await expect(modal).not.toBeVisible();

        // 6. Verify Table Summary (The machinery renders summaries of our unsaved state)
        const newRow = page.locator('tr.cbi-section-table-row').last();
        await expect(newRow.locator('td[data-name="_emails"]')).toContainText('user1@example.com');
        await expect(newRow.locator('td[data-name="_emails"]')).toContainText('user2@example.com');
        await expect(newRow.locator('td[data-name="_groups"]')).toContainText('DevOps');
        await expect(newRow.locator('td[data-name="_read"]')).toContainText('superuser');
        await expect(newRow.locator('td[data-name="_write"]')).toContainText('superuser');

        // 7. Verify the Save button is enabled
        await expect(page.locator('.cbi-button-save')).not.toBeDisabled();
    });

    test('Logic: Internal Issuer URL placeholder follows hostname', async ({ page }) => {
        await setupPristineMocks(page);
        await loginAsRoot(page);
        await gotoSSOSettings(page);

        const internalIssuer = page.locator('[id="widget.cbid.luci-sso.default.internal_issuer_url"]');
        await expect(internalIssuer).toHaveAttribute('placeholder', /https:\/\/.*:8443/);
    });

});
