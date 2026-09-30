'use strict';
const { expect } = require('@playwright/test');

// How long to wait for an rpcd reload (a luci-sso write) to finish. The
// reload itself takes about two seconds: one second until the plugin signals
// rpcd, then rpcd's restart. The rest covers a stall of uhttpd: it checks
// every /ubus/ call's session with a synchronous call to rpcd, waiting up to
// half its script timeout (60 s by default, so 30 s), and serves nothing
// meanwhile. A check that reaches rpcd just as it re-executes itself is never
// answered, so one unlucky poll freezes uhttpd for those 30 s. The wait still
// ends on an exact condition: list_roles, answered, with reload_pending false.
const RELOAD_WAIT_MS = 45000;

async function loginAsRoot(page) {
    await page.goto('/');
    await page.fill('input[name="luci_username"]', 'root');
    await page.fill('input[name="luci_password"]', 'admin');
    await page.click('button.cbi-button-positive');
    await page.waitForURL(/\/cgi-bin\/luci/);
}

async function gotoSSOSettings(page) {
    await page.goto('/cgi-bin/luci/admin/services/sso');
    // Dismiss any leftover LuCI alert overlays from previous failed attempts
    if (await page.locator('#modal_overlay').isVisible()) {
        await page.keyboard.press('Escape');
    }
    await page.waitForSelector('.cbi-map');
}

// Logs in through the SSO button. The mock IdP signs in admin@example.com
// without a prompt and redirects straight back to LuCI.
async function loginViaSSO(page) {
    await page.context().clearCookies();
    await page.goto('/');
    await page.locator('#luci-sso-login-btn').click();
    await page.locator('a[href*="/logout"]').waitFor({ state: 'visible', timeout: 5000 });
}

// Calls rpcd over /ubus/ with the page's own LuCI session and returns
// { status, data }. A call the session's ACL refuses comes back as status
// 'denied' (JSON-RPC -32002, or the uci plugin's ubus status 6). A call that
// reaches rpcd while it restarts is never answered, so each call gives up
// after two seconds with status 'timeout'.
async function ubus(page, obj, method, params) {
    const reply = await page.evaluate(async ([o, m, p]) => {
        try {
            const r = await fetch('/ubus/', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'call', params: [L.env.sessionid, o, m, p] }),
                signal: AbortSignal.timeout(2000),
            });
            return await r.json();
        } catch (e) {
            return { error: { code: 'timeout' } };
        }
    }, [obj, method, params]);
    if (reply.error)
        return { status: reply.error.code === -32002 ? 'denied' : reply.error.code, data: null };
    return { status: reply.result[0] === 6 ? 'denied' : reply.result[0], data: reply.result[1] };
}

// The luci-sso ubus object's roles (rpcd login entries), by name, once no
// rpcd reload is pending.
async function listRoles(page) {
    const deadline = Date.now() + RELOAD_WAIT_MS;
    for (;;) {
        const r = await ubus(page, 'luci-sso', 'list_roles', {});
        if (r.status === 0 && r.data.reload_pending === false)
            return Object.fromEntries(r.data.roles.map(x => [x.name, { read: x.read, write: x.write }]));
        if (Date.now() > deadline) throw new Error('rpcd did not finish reloading');
        await page.waitForTimeout(250);
    }
}

// The settings page's tabs: 'provider' (the default) or 'advanced'.
async function openTab(page, tab) {
    await page.locator(`.cbi-tabmenu li[data-tab="${tab}"] a`).click();
}

function modal(page) {
    return page.locator('#modal_overlay .modal');
}

// Adds values to a DynamicList of `scope` (the role editor, usually). Read
// and write access offer the router's access groups in a combobox, whose
// "custom" box takes any name or pattern; the other lists are text boxes.
async function fillList(scope, name, values) {
    const field = scope.locator(`[data-name="${name}"]`);
    for (const v of values) {
        const dropdown = field.locator('.cbi-dropdown');
        if (await dropdown.count()) {
            await dropdown.click();
            const custom = field.locator('input.create-item-input:visible');
            await custom.fill(v);
            await custom.press('Enter');
            await expect(field.locator('.item', { hasText: v }).last()).toBeAttached();
        } else {
            await field.locator('input[type="text"]').last().fill(v);
            await field.locator('.cbi-button-add').click();
        }
    }
}

// Save & Apply. With permission edits (`access`), LuCI applies the UCI
// changes, the page then writes the permissions and waits for rpcd to reload,
// and reloads itself. Without, LuCI applies and reloads, or says there is
// nothing to apply. The apply must be confirmed before the test moves on, or
// LuCI rolls it back.
async function saveAndApply(page, { access = true } = {}) {
    await page.locator('.cbi-page-actions .cbi-button-apply').first().click();
    if (access) {
        await expect(page.locator('.alert-message', { hasText: 'Role permissions saved and in force.' }))
            .toBeVisible({ timeout: RELOAD_WAIT_MS + 60000 });
        await page.waitForEvent('load', { timeout: 30000 });
    } else {
        const applied = page.getByText('Configuration changes applied.');
        const none = page.getByText('There are no changes to apply');
        await expect(applied.or(none)).toBeVisible({ timeout: 60000 });
        if (await applied.isVisible())
            await page.waitForEvent('load', { timeout: 30000 });
    }
    await page.waitForSelector('.cbi-map');
    await expect(page.getByText('Session expired')).toHaveCount(0);
}

module.exports = { loginAsRoot, gotoSSOSettings, loginViaSSO, ubus, listRoles, openTab, modal, fillList, saveAndApply, RELOAD_WAIT_MS };
