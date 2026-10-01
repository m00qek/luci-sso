'use strict';
const os = require('os');
const { test, expect } = require('@playwright/test');
const { loginAsRoot, gotoSSOSettings, openTab, ubus } = require('./helpers');

// The trusted_proxy option, through the real uhttpd and CGI. These tests run
// in the browser container, which reaches LuCI from its own address on the
// Docker network: trusting exactly that address makes this container the
// "reverse proxy". Only REMOTE_ADDR counts, so no header is sent.
//
// Every login start that is not exempt spends the browser's budget, so the
// tests run in order, and the last one uses it up. test.sh resets the
// rate-limit state before each spec file.

const LOGIN = '/cgi-bin/luci-sso';
const LIMIT = 10; // login starts per client per 5 minutes

// This container's own addresses, as uhttpd sees them.
function ownAddresses() {
    const out = [];
    for (const list of Object.values(os.networkInterfaces()))
        for (const a of list || [])
            if (!a.internal && a.family === 'IPv4') out.push(a.address);
    return out;
}

async function setTrusted(page, list) {
    await loginAsRoot(page);
    if (list.length)
        await ubus(page, 'uci', 'set', { config: 'luci-sso', section: 'default', values: { trusted_proxy: list } });
    else
        await ubus(page, 'uci', 'delete', { config: 'luci-sso', section: 'default', option: 'trusted_proxy' });
    // LuCI sessions may not `uci commit`; they stage, then apply.
    await ubus(page, 'uci', 'apply', { rollback: false });
    const r = await ubus(page, 'uci', 'get', { config: 'luci-sso', section: 'default', option: 'trusted_proxy' });
    expect((r.status === 0 && r.data) ? r.data.value : [], 'trusted_proxy as saved').toEqual(list);
}

async function loginStart(request) {
    return (await request.get(LOGIN, { maxRedirects: 0 })).status();
}

test.describe.configure({ mode: 'serial' });

test.describe('Trusted proxy', () => {
    test.afterAll(async ({ browser }) => {
        const page = await browser.newPage();
        await setTrusted(page, []);
        await page.close();
    });

    test('the Advanced tab takes addresses and CIDR ranges, and refuses anything else', async ({ page }) => {
        await loginAsRoot(page);
        await gotoSSOSettings(page);
        await openTab(page, 'advanced');
        const field = page.locator('[data-name="trusted_proxy"]');
        await expect(field).toBeVisible();
        await expect(field).toContainText('Only if LuCI sits behind a reverse proxy on this address');
        await expect(field).toContainText('so the proxy must limit clients itself');
        // LuCI validates the box on keyup and blur.
        const input = field.locator('input[type="text"]').last();
        for (const good of ['127.0.0.1', '10.0.0.0/8', '::1', '2001:db8::/32']) {
            await input.fill(good);
            await input.dispatchEvent('keyup');
            await expect(input, good).not.toHaveClass(/cbi-input-invalid/);
        }
        for (const bad of ['localhost', '10.0.0.0/33', '10.0.0.0/255.0.0.0', '1.2.3.4:80']) {
            await input.fill(bad);
            await input.dispatchEvent('keyup');
            await expect(input, bad).toHaveClass(/cbi-input-invalid/);
        }
    });

    // The notice this logs is checked by the unit and integration tests:
    // LuCI's session cannot read the system log over /ubus here.
    test('requests from the trusted address are never limited per client', async ({ page, request }) => {
        const own = ownAddresses();
        expect(own.length, 'this container has an address on the Docker network').toBeGreaterThan(0);
        await setTrusted(page, own);
        for (let i = 1; i <= LIMIT + 5; i++)
            expect(await loginStart(request), `login start ${i}`).toBe(302);
    });

    test('any other address is limited as before', async ({ page, request }) => {
        // The setting a proxy on the router would use: not this container.
        await setTrusted(page, ['127.0.0.1']);
        for (let i = 1; i <= LIMIT; i++)
            expect(await loginStart(request), `login start ${i}`).toBe(302);
        expect(await loginStart(request), `login start ${LIMIT + 1}`).toBe(429);
    });
});
