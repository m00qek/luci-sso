const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

// Path inside the browser container where the script is mounted
const scriptPath = '/app/luci-sso-login.js';

test.describe('Security: Protocol Enforcement', () => {

  test.beforeEach(async ({ page }) => {
    // Mock the enabled check globally for these tests
    await page.route('**/cgi-bin/luci-sso?action=enabled', route => {
      route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ enabled: true })
      });
    });
  });

  test('Logic: Enforce HTTPS redirect even from HTTP origin', async ({ page }) => {
    // Navigate to an INSECURE origin
    // Note: Playwright allows mocking http:// even if the browser usually redirects
    const mockUrl = 'http://luci.luci-sso.test/mock-login';
    
    await page.route(mockUrl, route => {
      route.fulfill({
        contentType: 'text/html',
        body: `
          <div class="cbi-page-actions">
            <button class="cbi-button-positive">Log in</button>
          </div>
        `
      });
    });

    await page.goto(mockUrl);
    
    // Load the production script
    const scriptContent = fs.readFileSync(scriptPath, 'utf8');
    await page.addScriptTag({ content: scriptContent });

    const ssoBtn = page.locator('#luci-sso-login-btn');
    await expect(ssoBtn).toBeVisible();

    // Set up interception for the redirect target and capture the URL
    let capturedUrl = '';
    await page.route('**/cgi-bin/luci-sso', route => {
      capturedUrl = route.request().url();
      route.fulfill({ status: 200, body: 'Intercepted' });
    });

    await ssoBtn.click();
    
    // Verify redirection happened and USED HTTPS
    await expect.poll(() => capturedUrl).toContain('https://');
    expect(capturedUrl).not.toContain('http://luci.luci-sso.test');
  });

});
