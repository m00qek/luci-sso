'use strict';
const { expect } = require('@playwright/test');

// How long to wait for permissions to be in force after an apply. The
// init script regenerates the rpcd login entries a second after the apply
// (procd's trigger delay), and rpcd's reload takes about two seconds more,
// once LuCI has confirmed the apply. The rest covers a stall of uhttpd: it
// checks every /ubus/ call's session with a synchronous call to rpcd, waiting
// up to half its script timeout (60 s by default, so 30 s), and serves
// nothing meanwhile. A check that reaches rpcd just as it re-executes itself
// is never answered, so one unlucky poll freezes uhttpd for those 30 s. The
// waits still end on an exact condition: an SSO session's rights, as rpcd
// answers for them.
const RELOAD_WAIT_MS = 45000;

// After an apply that changes no open session's rights, nothing tells the
// browser when the init script has regenerated the entries and rpcd has
// reloaded; this outlasts both, so the next login neither meets an entry its
// lists no longer generate nor reaches rpcd while it restarts.
const SETTLE_MS = 6000;

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

// rpcd's answer for the page's own session: may it `perm` ('read' or
// 'write') the access group? null while rpcd does not answer.
async function hasAccess(page, group, perm) {
    const r = await ubus(page, 'session', 'access', { scope: 'access-group', object: group, function: perm });
    return r.status === 0 ? r.data.access : null;
}

// Waits until the page's session, an SSO session, has (`expected` true) or
// lacks `perm` on `group`: once an apply's new rights are in force, rpcd has
// reloaded and rebuilt the session from its role's entry. Polls every two
// seconds: a poll that reaches rpcd while it re-executes itself freezes
// uhttpd (see RELOAD_WAIT_MS), so the fewer, the better.
async function awaitAccess(page, group, perm, expected) {
    const deadline = Date.now() + RELOAD_WAIT_MS;
    for (;;) {
        await page.waitForTimeout(2000);
        if (await hasAccess(page, group, perm) === expected)
            return;
        if (Date.now() > deadline)
            throw new Error(`the session never got ${perm} on ${group} = ${expected}`);
    }
}

// An option of a luci-sso (or `config`) section, as the page's session sees
// it: with the changes it has staged. null when it is not set (rpcd then
// answers with no data at all).
async function uciOption(page, section, option, config = 'luci-sso') {
    const r = await ubus(page, 'uci', 'get', { config, section, option });
    return (r.status === 0 && r.data) ? r.data.value : null;
}

// Waits for an apply that changes no open session's rights to settle (see
// SETTLE_MS).
async function settle(page) {
    await page.waitForTimeout(SETTLE_MS);
}

// Sets options of luci-sso sections, and of rpcd sections in `rpcd`, as root,
// and applies them unchecked, as `uci set` and `reload_config` would: the
// init script then makes rpcd reload. Each argument maps a section to its
// options; an option set to null is removed, as is a section set to null. A
// section of rpcd that does not exist yet is created as a login. The caller
// waits for the result (awaitAccess or settle).
async function applyAsRoot(browser, values, rpcd = {}) {
    const context = await browser.newContext();
    const page = await context.newPage();
    try {
        await loginAsRoot(page);
        for (const [config, sections] of [['luci-sso', values], ['rpcd', rpcd]]) {
            for (const [section, options] of Object.entries(sections)) {
                if (options === null) {
                    await ubus(page, 'uci', 'delete', { config, section });
                    continue;
                }
                if (config === 'rpcd' && (await ubus(page, 'uci', 'get', { config, section })).status !== 0)
                    await ubus(page, 'uci', 'add', { config, type: 'login', name: section });
                for (const [option, value] of Object.entries(options)) {
                    if (value === null)
                        await ubus(page, 'uci', 'delete', { config, section, option });
                    else
                        await ubus(page, 'uci', 'set', { config, section, values: { [option]: value } });
                }
            }
        }
        // 5 (UBUS_STATUS_NO_DATA): nothing changed, so nothing to apply.
        const r = await ubus(page, 'uci', 'apply', { rollback: false });
        expect([0, 5]).toContain(r.status);
    } finally {
        await context.close();
    }
}

// The options of a role's rpcd login entry, luci_sso_<role>, as the settings
// page stages them: username sso:<role>, the read list with `unauthenticated`
// unless it grants it already, and no write option for an empty list.
function entryFor(role, read, write) {
    const grants = read.some(g => g === '*' || g === 'unauthenticated');
    return {
        [`luci_sso_${role}`]: {
            username: `sso:${role}`,
            read: grants ? read : [...read, 'unauthenticated'],
            write: write.length ? write : null,
        },
    };
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

// Removes the item `value` of a DynamicList of `scope`: a click on its x,
// the right edge of the item.
async function removeListItem(scope, name, value) {
    const item = scope.locator(`[data-name="${name}"] .item`, { hasText: value }).first();
    const box = await item.boundingBox();
    await item.click({ position: { x: box.width - 4, y: box.height / 2 } });
    await expect(scope.locator(`[data-name="${name}"] .item`, { hasText: value })).toHaveCount(0);
}

// Waits for LuCI to report an apply, confirmed, and to reload the page.
async function awaitApplied(page) {
    const applied = page.getByText('Configuration changes applied.');
    const none = page.getByText('There are no changes to apply');
    await expect(applied.or(none)).toBeVisible({ timeout: 60000 });
    if (await applied.isVisible())
        await page.waitForEvent('load', { timeout: 30000 });
    await page.waitForSelector('.cbi-map');
    await expect(page.getByText('Session expired')).toHaveCount(0);
}

// The page footer's Save & Apply: saves the form and applies every staged
// change, with LuCI's rollback. It must be confirmed before the test moves
// on, or LuCI rolls it back.
async function saveAndApply(page) {
    await page.locator('.cbi-page-actions .cbi-button-apply').first().click();
    await awaitApplied(page);
}

// Save & Apply from LuCI's header: the "Unsaved Changes" indicator opens the
// changes dialog, whose Save & Apply applies everything staged, with LuCI's
// rollback. Unsaved edits in the form are not part of it.
async function applyFromHeader(page) {
    await page.locator('[data-indicator="uci-changes"]').click();
    await expect(modal(page).getByText('# /etc/config/luci-sso')).toBeVisible();
    await modal(page).locator('.cbi-button-positive', { hasText: 'Save & Apply' }).first().click();
    await awaitApplied(page);
}

module.exports = {
    loginAsRoot, gotoSSOSettings, loginViaSSO, ubus, hasAccess, awaitAccess, uciOption, settle, applyAsRoot, entryFor, openTab, modal,
    fillList, removeListItem, saveAndApply, applyFromHeader, RELOAD_WAIT_MS, SETTLE_MS,
};
