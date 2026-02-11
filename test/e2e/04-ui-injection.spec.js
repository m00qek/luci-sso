const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

// Path inside the browser container where the script is mounted
const scriptPath = '/app/luci-sso-login.js';

test.describe('UI: Login Button Injection', () => {

  test.beforeEach(async ({ page }) => {
    // Mock the enabled check globally for these tests
    await page.route('**/cgi-bin/luci-sso?action=enabled', route => {
      route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ enabled: true })
      });
    });
  });

  test('Logic: Static Button Detection', async ({ page }) => {
    // Navigate to a real origin so that page.route works
    await page.goto('https://luci.luci-sso.test/mock-ui-test');
    
    // Simulate a standard LuCI login page structure
    await page.setContent(`
      <div class="cbi-page-actions">
        <button class="cbi-button-positive">Log in</button>
      </div>
    `);

    // Load the production script
    await page.addScriptTag({ path: scriptPath });

    // Verify button and separator appear
    const ssoBtn = page.locator('#luci-sso-login-btn');
    const separator = page.locator('#luci-sso-separator');

    await expect(ssoBtn).toBeVisible();
    await expect(ssoBtn).toHaveText('Login with SSO');
    await expect(separator).toBeVisible();
    await expect(separator).toHaveText('— or —');
  });

  test('Logic: Dynamic Injection via MutationObserver', async ({ page }) => {
    await page.goto('https://luci.luci-sso.test/mock-ui-test');
    // Start with a blank page and script loaded
    await page.setContent('<div></div>');
    await page.addScriptTag({ path: scriptPath });

    await expect(page.locator('#luci-sso-login-btn')).not.toBeVisible();

    // Dynamically add the LuCI button (simulating LuCI.js rendering)
    await page.evaluate(() => {
      const container = document.querySelector('div');
      const btn = document.createElement('button');
      btn.className = 'cbi-button-positive';
      btn.textContent = 'Sign in';
      container.appendChild(btn);
    });

    // Should appear automatically after observer picks it up (debounced 100ms)
    await expect(page.locator('#luci-sso-login-btn')).toBeVisible({ timeout: 2000 });
  });

  test('Logic: Re-rendering Resilience (Auto-recovery)', async ({ page }) => {
    await page.goto('https://luci.luci-sso.test/mock-ui-test');
    await page.setContent(`
      <div class="cbi-page-actions">
        <button class="cbi-button-positive">Log in</button>
      </div>
    `);
    await page.addScriptTag({ path: scriptPath });
    await expect(page.locator('#luci-sso-login-btn')).toBeVisible();

    // Manually delete the SSO button (simulating LuCI clearing the container)
    await page.evaluate(() => {
      const el = document.getElementById('luci-sso-login-btn');
      if (el) el.remove();
    });

    // Should be re-injected by observer/polling loop
    await expect(page.locator('#luci-sso-login-btn')).toBeVisible({ timeout: 2000 });
  });

  test('Logic: Support Multi-language Heuristics', async ({ page }) => {
    const languages = ['Anmelden', 'Login', 'Sign in'];
    
    for (const lang of languages) {
      await page.goto('https://luci.luci-sso.test/mock-ui-test');
      await page.setContent(`
        <div>
          <button class="cbi-button-positive">${lang}</button>
        </div>
      `);
      
      // Re-evaluate script to trigger fresh injection
      const scriptContent = fs.readFileSync(scriptPath, 'utf8');
      await page.evaluate((code) => { eval(code); }, scriptContent);

      await expect(page.locator('#luci-sso-login-btn'), `Failed for language: ${lang}`).toBeVisible();
    }
  });

  test('Logic: Prevent Double Injection', async ({ page }) => {
    await page.goto('https://luci.luci-sso.test/mock-ui-test');
    await page.setContent(`
      <div class="cbi-page-actions">
        <button class="cbi-button-positive">Log in</button>
      </div>
    `);
    
    // Load the script multiple times
    await page.addScriptTag({ path: scriptPath });
    await page.addScriptTag({ path: scriptPath });
    await page.addScriptTag({ path: scriptPath });

    // Verify only ONE button exists
    const count = await page.locator('#luci-sso-login-btn').count();
    expect(count).toBe(1);
  });

  test('Logic: Correct Styling Enforcement', async ({ page }) => {
    await page.goto('https://luci.luci-sso.test/mock-ui-test');
    await page.setContent(`
      <div class="cbi-page-actions">
        <button class="cbi-button-positive">Log in</button>
      </div>
    `);
    await page.addScriptTag({ path: scriptPath });

    const ssoBtn = page.locator('#luci-sso-login-btn');
    const styles = await ssoBtn.evaluate((el) => {
      const s = window.getComputedStyle(el);
      return {
        background: s.background,
        color: s.color
      };
    });

    // Verify high-contrast blue gradient and white text
    // rgb(51, 122, 183) is #337ab7
    expect(styles.background).toContain('rgb(51, 122, 183)');
    expect(styles.color).toBe('rgb(255, 255, 255)');
  });

  test('Logic: Redirect on Click', async ({ page }) => {
    // Mock the login page itself to have a proper HTTPS origin
    const mockUrl = 'https://luci.luci-sso.test/mock-login';
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
    await page.addScriptTag({ path: scriptPath });

    const ssoBtn = page.locator('#luci-sso-login-btn');
    
    // Set up interception for the redirect target
    let redirected = false;
    await page.route('**/cgi-bin/luci-sso', route => {
      redirected = true;
      route.fulfill({ status: 200, body: 'Intercepted' });
    });

    await ssoBtn.click();
    
    // Verify redirection happened via network layer
    await expect.poll(() => redirected).toBe(true);
  });

  test('Integration: Real LuCI Login Page Detection', async ({ page }) => {
    // Navigate to the actual dev stack landing page
    await page.goto('/');
    
    // The script is injected by uci-defaults in the real container
    const ssoBtn = page.locator('#luci-sso-login-btn');
    await expect(ssoBtn).toBeVisible({ timeout: 5000 });
    
    // Ensure correct relative positioning (SSO button should follow Primary button)
    const isAfter = await page.evaluate(() => {
      const primary = document.querySelector('.cbi-button-positive');
      const sso = document.getElementById('luci-sso-login-btn');
      return !!(primary && sso && (primary.compareDocumentPosition(sso) & Node.DOCUMENT_POSITION_FOLLOWING));
    });
    expect(isAfter).toBeTruthy();
  });

});
