'use strict';

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
    let roles = null;
    for (let waited = 0; waited <= 15000; waited += 250) {
        const r = await ubus(page, 'luci-sso', 'list_roles', {});
        if (r.status === 0 && r.data.reload_pending === false) {
            roles = Object.fromEntries(r.data.roles.map(x => [x.name, { read: x.read, write: x.write }]));
            break;
        }
        await page.waitForTimeout(250);
    }
    if (!roles) throw new Error('rpcd did not finish reloading');
    return roles;
}

module.exports = { loginAsRoot, gotoSSOSettings, loginViaSSO, ubus, listRoles };
