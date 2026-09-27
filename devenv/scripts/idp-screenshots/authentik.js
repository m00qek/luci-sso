'use strict';

// Authentik admin steps of docs/how-to/providers/authentik.md. Run by
// authentik.sh; see common.js for the capture rules.
//
// The provider form is a wizard whose body scrolls inside a fixed-height
// dialog, so it is captured in three parts, each scrolled into view first.
//
//   authentik-provider-name.png         Provider Name, Authorization Flow and
//                                       Client Type
//   authentik-provider-redirects.png    Redirect URIs/Origins (RegEx): the
//                                       Authorization and Post Logout entries,
//                                       and Add entry
//   authentik-provider-signing-key.png  Signing Key, preselected
//   authentik-new-application-menu.png  New Application ▸ with Existing
//                                       Provider...
//   authentik-application-form.png      Create Application: name, slug and
//                                       provider

const { launch, settle, shot, hide, run } = require('./common');

const AK = `https://${process.env.HOST}`;
const ROUTER = 'https://router.example.com';
const LONG = { timeout: 90000 };

// Scrolls an element to the middle of the scrolling panel that holds it.
async function scrollToCenter(locator) {
  await locator.evaluate((el) => el.scrollIntoView({ block: 'center' }));
  await locator.page().waitForTimeout(500);
}

run(async () => {
  // Wider than the default, so the redirect URI fields show whole URLs.
  const { browser, page } = await launch({ width: 1600 });

  // akadmin, with the bootstrap password.
  await page.goto(`${AK}/if/flow/default-authentication-flow/?next=%2Fif%2Fadmin%2F`);
  await page.locator('input[name=uidField]').waitFor(LONG);
  await page.locator('input[name=uidField]').fill('akadmin');
  await page.keyboard.press('Enter');
  // The password stage re-renders once after it appears: type, then check.
  const password = page.getByPlaceholder('Please enter your password');
  await password.waitFor(LONG);
  await page.waitForTimeout(1500);
  await password.pressSequentially(process.env.ADMIN_PASSWORD);
  if (await password.inputValue() !== process.env.ADMIN_PASSWORD) throw new Error('password not typed');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.waitForFunction(() => location.pathname.startsWith('/if/admin'), null, LONG);

  // Applications > Providers > New Provider > OAuth2/OpenID Provider.
  await page.goto(`${AK}/if/admin/#/core/providers`);
  const newProvider = page.getByRole('button', { name: 'New Provider' }).first();
  await newProvider.waitFor(LONG);
  await settle(page, 1500);
  await newProvider.click();
  // Depending on the layout, choosing the tile moves the wizard on by itself
  // or waits for Next.
  await page.locator('dialog[open]').getByText('OAuth2/OpenID Provider', { exact: true }).click();
  await page.waitForTimeout(1500);
  if (!await page.locator('input[name=name]').isVisible()) {
    await page.getByRole('button', { name: 'Next' }).click();
  }
  await page.locator('input[name=name]').waitFor(LONG);
  await settle(page, 1500);

  await page.locator('input[name=name]').fill('luci-router');
  await page.locator('input[name=authorizationFlow]').click();
  await page.getByText('default-provider-authorization-explicit-consent').first().click();
  await page.waitForTimeout(800);
  await hide(page.locator('input[name=clientSecret]'));

  const intro = page.getByText('OAuth2 Provider for generic OAuth').first();
  await scrollToCenter(intro);
  await shot(page, 'authentik-provider-name',
    [page.getByText('Provider Name', { exact: true }).first(), page.locator('input[name=authorizationFlow]'),
      page.getByText('Public clients are incapable', { exact: false })]);

  // Two redirect URIs: the callback (Authorization) and the post-logout
  // return address (Post Logout).
  const addEntry = page.getByRole('button', { name: 'Add entry' });
  await addEntry.scrollIntoViewIfNeeded();
  await addEntry.click();
  await page.locator('input[name=url]').nth(0).fill(`${ROUTER}/cgi-bin/luci-sso/callback`);
  await addEntry.click();
  await page.locator('select[name=redirectUriType]').nth(1).selectOption({ label: 'Post Logout' });
  await page.locator('input[name=url]').nth(1).fill(`${ROUTER}/`);
  // Show each URL from its start, not from where the typing ended.
  await page.locator('input[name=url]').evaluateAll((inputs) => inputs.forEach((el) => {
    el.blur();
    el.scrollLeft = 0;
  }));
  const redirects = page.getByText('Redirect URIs/Origins (RegEx)', { exact: true });
  await scrollToCenter(redirects);
  await shot(page, 'authentik-provider-redirects',
    [redirects, page.locator('input[name=url]').nth(1), addEntry], { minWidth: 800 });

  const signingKey = page.locator('input[name=signingKey]');
  const signingKeyHelp = page.getByText('Key used to sign tokens.', { exact: false });
  await signingKeyHelp.scrollIntoViewIfNeeded();
  await page.waitForTimeout(500);
  await shot(page, 'authentik-provider-signing-key',
    [page.getByText('Signing Key', { exact: true }).first(), signingKey, signingKeyHelp]);

  await page.getByRole('button', { name: 'Create' }).click();
  await settle(page, 3000);

  // Applications > Applications > New Application ▸ with Existing Provider...
  await page.goto(`${AK}/if/admin/#/core/applications`);
  const options = page.getByRole('button', { name: 'New Application options' }).first();
  await options.waitFor(LONG);
  await settle(page, 1500);
  await options.click();
  const existing = page.getByText(/with Existing Provider/).filter({ visible: true }).first();
  await existing.waitFor();
  await page.waitForTimeout(500);
  await shot(page, 'authentik-new-application-menu',
    [page.getByRole('button', { name: 'New Application', exact: true }).first(), options, existing],
    { margin: 24 });
  await existing.click();

  const name = page.locator('input[name=name]').first();
  await name.waitFor(LONG);
  await name.pressSequentially('LuCI Router', { delay: 30 });
  await page.locator('input[name=slug]').fill('luci-router');
  await page.locator('input[name=provider]').click();
  await page.getByRole('option', { name: /^luci-router/ }).first().click()
    .catch(() => page.getByText('luci-router', { exact: true }).last().click());
  await page.waitForTimeout(800);
  await shot(page, 'authentik-application-form',
    [page.getByText('Application Name', { exact: true }).first(), name,
      page.locator('input[name=provider]'), page.getByRole('button', { name: 'Create Application' })],
    { minWidth: 800 });

  await browser.close();
});
