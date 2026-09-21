const { test, expect } = require('@playwright/test');
const fs = require('fs');

// Path inside the browser container where the production script is mounted
// (devenv/docker-compose.ci.yaml). It is the live working-tree file, so these
// tests exercise whatever is currently in files/www/luci-static/resources/.
const scriptPath = '/app/luci-sso-login.js';

// A real origin is required for page.route / relative navigation to behave.
const ORIGIN = 'https://luci.luci-sso.test/mock-theme-test';

// The two login-button markups that exist upstream. Issue #10: only BOOTSTRAP
// was ever handled, so the SSO button was invisible on every other theme.
//
//   bootstrap  — themes/luci-theme-bootstrap/ucode/template/themes/bootstrap/sysauth.ut
//   generic    — modules/luci-base/ucode/template/sysauth.ut
//                used by material, openwrt, openwrt-2020 and footstrap
const BOOTSTRAP_BTN = '<button class="btn cbi-button-positive important">Log in</button>';
const GENERIC_BTN =
  '<input type="submit" value="Log in" class="btn cbi-button cbi-button-apply" />';

const wrap = (inner) => `<div class="cbi-page-actions">${inner}</div>`;

test.describe('UI: Login Button Injection Across Themes', () => {

  test('Generic sysauth.ut markup gets the SSO button (issue #10)', async ({ page }) => {
    // Regression for the primary cause: the old selector
    // '.cbi-button-positive, .btn.login, button.important' matched none of the
    // generic markup — it is an <input>, carries no 'login' class, and has no
    // cbi-button-positive. This is the case every non-bootstrap theme hits.
    await page.goto(ORIGIN);
    await page.setContent(wrap(GENERIC_BTN));
    await page.addScriptTag({ path: scriptPath });

    await expect(page.locator('#luci-sso-login-btn')).toBeVisible();
    await expect(page.locator('#luci-sso-login-btn')).toHaveText('Login with SSO');
    await expect(page.locator('#luci-sso-separator')).toBeVisible();
  });

  test('Label is read from value= on <input>, not textContent', async ({ page }) => {
    // Isolates the second defect behind #10. An <input> keeps its label in the
    // value attribute, so textContent is ''. Here the element matches the
    // selector via cbi-button-positive but has NO cbi-button-apply, so the only
    // route to a match is the label heuristic actually reading value=.
    await page.goto(ORIGIN);
    await page.setContent(wrap(
      '<input type="submit" value="Log in" class="btn cbi-button cbi-button-positive" />'
    ));
    await page.addScriptTag({ path: scriptPath });

    await expect(page.locator('#luci-sso-login-btn')).toBeVisible();
  });

  test('Multi-language labels on the generic input', async ({ page }) => {
    // 04-ui-injection covers these for <button> only; value= was never exercised.
    for (const label of ['Anmelden', 'Login', 'Sign in']) {
      await page.goto(ORIGIN);
      await page.setContent(wrap(
        `<input type="submit" value="${label}" class="btn cbi-button cbi-button-positive" />`
      ));
      const code = fs.readFileSync(scriptPath, 'utf8');
      await page.evaluate((c) => { eval(c); }, code);

      await expect(
        page.locator('#luci-sso-login-btn'),
        `Failed for label: ${label}`
      ).toBeVisible();
    }
  });

  test('Bootstrap markup still works after the selector change', async ({ page }) => {
    // Guards the original path against regression from widening the selector.
    await page.goto(ORIGIN);
    await page.setContent(wrap(BOOTSTRAP_BTN));
    await page.addScriptTag({ path: scriptPath });

    await expect(page.locator('#luci-sso-login-btn')).toBeVisible();
  });

  test('No double injection on generic markup', async ({ page }) => {
    // The fix copies primaryBtn.className onto the injected button, so on
    // generic markup the SSO button itself now carries cbi-button-apply and
    // matches the widened selector. Only the BTN_ID early-return stops it being
    // re-selected as its own "primary" control; assert that holds.
    await page.goto(ORIGIN);
    await page.setContent(wrap(GENERIC_BTN));
    await page.addScriptTag({ path: scriptPath });
    await page.addScriptTag({ path: scriptPath });
    await page.addScriptTag({ path: scriptPath });

    // Give the MutationObserver (100ms debounce) time to run on its own output.
    await page.waitForTimeout(500);

    expect(await page.locator('#luci-sso-login-btn').count()).toBe(1);
    expect(await page.locator('#luci-sso-separator').count()).toBe(1);
  });

  test('SSO button follows the primary control on generic markup', async ({ page }) => {
    await page.goto(ORIGIN);
    await page.setContent(wrap(GENERIC_BTN));
    await page.addScriptTag({ path: scriptPath });
    await expect(page.locator('#luci-sso-login-btn')).toBeVisible();

    const isAfter = await page.evaluate(() => {
      const primary = document.querySelector('input.cbi-button-apply');
      const sso = document.getElementById('luci-sso-login-btn');
      return !!(primary && sso &&
        (primary.compareDocumentPosition(sso) & Node.DOCUMENT_POSITION_FOLLOWING));
    });
    expect(isAfter).toBeTruthy();
  });

  test('Injected button does not submit the surrounding form', async ({ page }) => {
    // On generic markup the primary control is a submit input inside a <form>.
    // The SSO button is appended into that same form, so if it were not
    // type="button" clicking it would submit the login form instead of starting
    // the SSO flow — silently reproducing "stays on the login page".
    await page.goto(ORIGIN);
    await page.setContent(
      `<form action="/should-not-submit" method="post">${wrap(GENERIC_BTN)}</form>`
    );
    await page.addScriptTag({ path: scriptPath });

    const type = await page.locator('#luci-sso-login-btn').getAttribute('type');
    expect(type).toBe('button');
  });

});
