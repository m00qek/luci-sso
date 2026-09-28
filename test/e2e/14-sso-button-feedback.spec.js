const { test, expect } = require('@playwright/test');

// Path inside the browser container where the production script is mounted.
const scriptPath = '/app/luci-sso-login.js';

// A real origin, so page.route and the button's https:// redirect behave.
const ORIGIN = 'https://luci.luci-sso.test/mock-feedback-test';

// The script's IDP_TIMEOUT_MS. The tests drive the page's clock with
// page.clock, so they do not wait for it in real time.
const IDP_TIMEOUT_MS = 15000;

const TIMEOUT_TEXT = 'The identity provider is not responding. ' +
  'Check that this device can reach it, then try again.';

// True when the page shows [Log in], "— or —", [Login with SSO], as three
// consecutive siblings in that order.
async function orderIsRight(page, primarySelector) {
  return page.evaluate((sel) => {
    const primary = document.querySelector(sel);
    const sep = document.getElementById('luci-sso-separator');
    const sso = document.getElementById('luci-sso-login-btn');
    if (!primary || !sep || !sso) return false;
    const follows = (a, b) => !!(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    return follows(primary, sep) && follows(sep, sso) &&
      primary.nextElementSibling === sep && sep.nextElementSibling === sso;
  }, primarySelector);
}

test.describe('UI: SSO button feedback', () => {

  test.describe('Real login page', () => {

    test.beforeEach(async ({ context }) => {
      await context.clearCookies();
    });

    test('The button is blue and sits after the Log in button, "— or —" between them', async ({ page }) => {
      await page.goto('/');
      const sso = page.locator('#luci-sso-login-btn');
      await expect(sso).toBeVisible();

      // Bootstrap moves the login form into a modal; check once it is there.
      await expect(page.locator('.modal #luci-sso-login-btn')).toBeVisible();
      expect(await orderIsRight(page, '.modal .cbi-button-positive')).toBe(true);

      // The theme's blue action style, not a copy of the green Log in button.
      await expect(sso).toHaveClass(/\bcbi-button-action\b/);
      await expect(sso).not.toHaveClass(/cbi-button-positive|cbi-button-apply/);
      const look = (sel) => page.locator(sel).evaluate((el) => {
        const s = window.getComputedStyle(el);
        return s.backgroundImage + ' ' + s.backgroundColor + ' ' + s.borderTopColor;
      });
      expect(await look('#luci-sso-login-btn')).not.toBe(await look('.modal .cbi-button-positive'));
      const inline = await sso.evaluate((el) => el.style.background + el.style.color + el.style.borderColor);
      expect(inline).toBe('');
    });

    test('An unreachable IdP gives the button back with a message, and password login still works', async ({ page }) => {
      // The browser never gets to the IdP. The router is asked for real and
      // must answer with its redirect to the IdP, but Playwright does not
      // route a redirect's target, so the redirect itself is replaced with a
      // 204. A 204 ends the navigation and leaves the page as it is, exactly
      // what the user sees while the browser hangs on an unreachable IdP. (A
      // navigation left pending instead would stall every Playwright locator
      // until it finished.)
      let attempts = 0;
      await page.route(/\/cgi-bin\/luci-sso$/, async (route) => {
        const response = await route.fetch({ maxRedirects: 0 });
        expect(response.status()).toBe(302);
        expect(new URL(response.headers()['location']).host).toBe(process.env.FQDN_IDP);
        attempts++;
        await route.fulfill({ status: 204 });
      });

      await page.clock.install();

      await test.step('Given the user is on the LuCI login page', async () => {
        await page.goto('/');
        await expect(page.locator('#luci-sso-login-btn')).toBeVisible();
      });

      const sso = page.locator('#luci-sso-login-btn');
      const msg = page.locator('#luci-sso-message');

      await test.step('When they click Login with SSO and the IdP does not answer', async () => {
        await sso.click();
        await expect.poll(() => attempts).toBe(1);
        await expect(sso).toBeDisabled();
        await expect(sso).toHaveText('Redirecting...');

        await page.clock.fastForward(IDP_TIMEOUT_MS - 1000);
        await expect(msg).toHaveCount(0);
        await expect(sso).toHaveText('Redirecting...');

        await page.clock.fastForward(1000);
      });

      await test.step('Then the message appears and the button is usable again', async () => {
        await expect(msg).toBeVisible();
        await expect(msg).toHaveText(TIMEOUT_TEXT);
        await expect(msg).toHaveClass(/\balert-message\b/);
        await expect(msg).toHaveClass(/\bwarning\b/);
        await expect(sso).toBeEnabled();
        await expect(sso).toHaveText('Login with SSO');
        expect(await orderIsRight(page, '.modal .cbi-button-positive')).toBe(true);
        // The message sits right under the SSO button.
        expect(await sso.evaluate((el) => el.nextElementSibling && el.nextElementSibling.id)).toBe('luci-sso-message');
      });

      await test.step('And a second click starts a fresh attempt', async () => {
        await sso.click();
        await expect.poll(() => attempts).toBe(2);
        await expect(msg).toHaveCount(0);
        await expect(sso).toBeDisabled();
        await expect(sso).toHaveText('Redirecting...');

        await page.clock.fastForward(IDP_TIMEOUT_MS);
        await expect(msg).toHaveText(TIMEOUT_TEXT);
        await expect(sso).toBeEnabled();
        await expect(sso).toHaveText('Login with SSO');
      });

      await test.step('And the password form still logs in', async () => {
        await page.fill('input[name="luci_username"]', 'root');
        await page.fill('input[name="luci_password"]', 'admin');
        await page.click('button.cbi-button-positive');
        await page.waitForURL(/\/cgi-bin\/luci/);
        await expect(page.locator('a[href*="/logout"]')).toBeVisible();
      });
    });
  });

  test.describe('Script logic', () => {

    test.beforeEach(async ({ page }) => {
      await page.route('**/cgi-bin/luci-sso?action=enabled', route => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ enabled: true }),
      }));
      // The redirect never leaves the page (see the real login page test).
      await page.route(/\/cgi-bin\/luci-sso$/, route => route.fulfill({ status: 204 }));
      await page.clock.install();
      await page.goto(ORIGIN);
    });

    test('A scrambled order is put back', async ({ page }) => {
      await page.setContent(`
        <div class="cbi-page-actions">
          <button class="btn cbi-button-positive important">Log in</button>
        </div>
      `);
      await page.addScriptTag({ path: scriptPath });
      await expect(page.locator('#luci-sso-login-btn')).toBeVisible();
      expect(await orderIsRight(page, '.cbi-button-positive')).toBe(true);

      // [Log in] [Login with SSO] "— or —", as seen on a real router.
      await page.evaluate(() => {
        const sep = document.getElementById('luci-sso-separator');
        sep.parentNode.appendChild(sep);
      });
      await expect.poll(() => orderIsRight(page, '.cbi-button-positive')).toBe(true);
    });

    test('The order holds when the form is moved into a modal', async ({ page }) => {
      // As the bootstrap view does: every child of the section is moved into
      // a modal, which may happen after the button was injected.
      await page.setContent(`
        <section>
          <form><input name="luci_password" type="password"></form>
          <button class="btn cbi-button-positive important">Log in</button>
        </section>
        <div id="modal_overlay"></div>
      `);
      await page.addScriptTag({ path: scriptPath });
      await expect(page.locator('#luci-sso-login-btn')).toBeVisible();

      await page.evaluate(() => {
        const dlg = document.createElement('div');
        dlg.className = 'modal login';
        document.getElementById('modal_overlay').appendChild(dlg);
        // The SSO nodes first, then the Log in button: the worst order.
        const nodes = Array.from(document.querySelectorAll('section > *')).reverse();
        nodes.forEach((n) => dlg.appendChild(n));
        document.querySelector('section').hidden = true;
      });
      await expect(page.locator('.modal #luci-sso-login-btn')).toBeVisible();
      await expect.poll(() => orderIsRight(page, '.modal .cbi-button-positive')).toBe(true);
      await expect(page.locator('#luci-sso-login-btn')).toHaveCount(1);
      await expect(page.locator('#luci-sso-separator')).toHaveCount(1);
    });

    test('Leaving the page stops the timer, so a slow redirect shows no message', async ({ page }) => {
      await page.setContent(`<div><button class="cbi-button-positive">Log in</button></div>`);
      await page.addScriptTag({ path: scriptPath });
      const sso = page.locator('#luci-sso-login-btn');
      await sso.click();
      await expect(sso).toHaveText('Redirecting...');

      await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: false })));
      await page.clock.fastForward(IDP_TIMEOUT_MS * 2);
      await expect(page.locator('#luci-sso-message')).toHaveCount(0);
      await expect(sso).toHaveText('Redirecting...');
    });

    test('Coming back with the Back button resets the button', async ({ page }) => {
      await page.setContent(`<div><button class="cbi-button-positive">Log in</button></div>`);
      await page.addScriptTag({ path: scriptPath });
      const sso = page.locator('#luci-sso-login-btn');

      // A first attempt timed out, and the second one left the page.
      await sso.click();
      await page.clock.fastForward(IDP_TIMEOUT_MS);
      await expect(page.locator('#luci-sso-message')).toBeVisible();
      await sso.click();
      await expect(sso).toBeDisabled();
      await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));

      // Restored from the back/forward cache.
      await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
      await expect(sso).toBeEnabled();
      await expect(sso).toHaveText('Login with SSO');
      await expect(page.locator('#luci-sso-message')).toHaveCount(0);
    });

    test('The message is plain text in the theme alert style', async ({ page }) => {
      await page.setContent(`<div><button class="cbi-button-positive">Log in</button></div>`);
      await page.addScriptTag({ path: scriptPath });
      await page.locator('#luci-sso-login-btn').click();
      await page.clock.fastForward(IDP_TIMEOUT_MS);

      const msg = page.locator('#luci-sso-message');
      await expect(msg).toHaveAttribute('role', 'alert');
      expect(await msg.evaluate((el) => el.children.length)).toBe(0);
      const inline = await msg.evaluate((el) => el.style.background + el.style.color + el.style.borderColor);
      expect(inline).toBe('');
    });
  });
});
