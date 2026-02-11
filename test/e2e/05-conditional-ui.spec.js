const { test, expect } = require('@playwright/test');
const { execSync } = require('child_process');

test.describe('UI: Conditional SSO Button', () => {

  // Helper to change UCI settings inside the openwrt container
  const setSsoEnabled = (enabled) => {
    const value = enabled ? '1' : '0';
    // We use 'docker exec' to reach the container from the host where tests run
    // The browser container can't directly exec on openwrt, but the test runner (Host) can.
    // However, in this dev environment, the test runner is in a container too?
    // Let's check how other tests do it.
    
    // Correction: In this project, E2E tests run in the 'browser' container.
    // The 'browser' container can reach 'openwrt' via network (ubus/http), 
    // but for UCI changes we usually rely on pre-configured states or a helper.
    
    // If we can't exec, we could use the /cgi-bin/luci-sso?action=... but we don't have a 'set' action.
    // Let's use 'ssh' or 'ubus' if available, but simplest is to assume the 
    // test runner has access to the docker socket or we use a specialized helper.
  };

  test('UI: Button is hidden when SSO is disabled', async ({ page }) => {
    // 1. Ensure SSO is enabled first (Baseline)
    // In this environment, we can't easily run 'docker exec' from inside the browser container.
    // But we CAN use the real CGI which we just modified.
    
    // Instead of changing UCI (complex for E2E logic in containers), 
    // we can mock the network response for the 'enabled' check to verify the JS logic.
    
    await page.goto('/');
    
    // Mock the enabled check to return false
    await page.route('**/cgi-bin/luci-sso?action=enabled', route => {
      route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ enabled: false })
      });
    });

    // The script is already injected by LuCI in this environment.
    // We wait to see if the button appears. It should NOT.
    const ssoBtn = page.locator('#luci-sso-login-btn');
    
    // Wait a bit to ensure the async fetch and MutationObserver had time to run
    await page.waitForTimeout(1000);
    await expect(ssoBtn).not.toBeVisible();
  });

  test('UI: Button is visible when SSO is enabled', async ({ page }) => {
    await page.goto('/');
    
    // Mock the enabled check to return true
    await page.route('**/cgi-bin/luci-sso?action=enabled', route => {
      route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ enabled: true })
      });
    });

    const ssoBtn = page.locator('#luci-sso-login-btn');
    await expect(ssoBtn).toBeVisible({ timeout: 5000 });
  });

  test('UI: Failsafe - Button is hidden if the enabled check fails', async ({ page }) => {
    await page.goto('/');
    
    // Mock the enabled check to fail (500)
    await page.route('**/cgi-bin/luci-sso?action=enabled', route => {
      route.fulfill({ status: 500 });
    });

    const ssoBtn = page.locator('#luci-sso-login-btn');
    await page.waitForTimeout(1000);
    await expect(ssoBtn).not.toBeVisible();
  });
});
