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

module.exports = { loginAsRoot, gotoSSOSettings };
