'use strict';

// Pocket ID admin steps of docs/how-to/providers/pocket-id.md and
// docs/tutorials/pocket-id-sso-login.md. Run by pocket-id.sh; see common.js
// for the capture rules.
//
// Pocket ID has no passwords: the first administrator signs up at /setup and
// registers a passkey, here on Chromium's virtual WebAuthn authenticator.
//
//   pocket-id-add-group.png        Create User Group: Friendly Name and Name
//   pocket-id-client-form.png      Create OIDC Client: Name, Callback URLs and
//                                  Logout Callback URLs, each added with Add
//   pocket-id-credentials.png      the client's Credentials tab before any
//                                  secret exists: Add client secret
//   pocket-id-allowed-groups.png   the client's Allowed User Groups tab as a
//                                  new client has it: no group, Unrestrict

const { launch, settle, shot, run } = require('./common');

const ID = `https://${process.env.HOST}`;
const ROUTER = 'https://router.example.com';

async function addPasskeyAuthenticator(context, page) {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
}

run(async () => {
  const { browser, context, page } = await launch();
  await addPasskeyAuthenticator(context, page);

  // The first administrator, and their passkey.
  await page.goto(`${ID}/setup`);
  await settle(page, 2000);
  await page.fill('#username', 'admin');
  await page.fill('#email', 'admin@example.com');
  await page.fill('#first-name', 'Ada');
  await page.fill('#last-name', 'Admin');
  await page.click('button:has-text("Sign Up")');
  await settle(page, 3000);
  await page.locator('button:has-text("Add Passkey")').last().click();
  await settle(page, 3000);

  // Administration > User Groups > Add Group.
  await page.goto(`${ID}/settings/admin/user-groups`);
  await settle(page, 2000);
  await page.click('button:has-text("Add Group")');
  await settle(page);
  const group = page.locator('form').first();
  await group.locator('#friendly-name').fill('Router Admins');
  await group.locator('#name').fill('router-admins');
  await shot(page, 'pocket-id-add-group',
    [page.getByText('Create User Group', { exact: true }), group]);
  await group.locator('button:has-text("Save")').click();
  await settle(page, 2500);

  // Administration > OIDC Clients > Add OIDC Client.
  await page.goto(`${ID}/settings/admin/oidc-clients`);
  await settle(page, 2000);
  await page.click('button:has-text("Add OIDC Client")');
  await settle(page, 1200);
  const client = page.locator('form').first();
  const add = client.getByRole('button', { name: 'Add', exact: true });
  await client.locator('#name').fill('luci-router');
  await add.first().click();
  await page.waitForTimeout(400);
  await client.locator('input[type=text]:not([id])').nth(0).fill(`${ROUTER}/cgi-bin/luci-sso/callback`);
  // The Callback URLs button is now "Add another": Logout Callback URLs has
  // the only "Add" left.
  await add.first().click();
  await page.waitForTimeout(400);
  await client.locator('input[type=text]:not([id])').nth(1).fill(`${ROUTER}/`);
  await page.locator('body').click({ position: { x: 5, y: 5 } });
  await shot(page, 'pocket-id-client-form',
    [page.getByText('Create OIDC Client', { exact: true }),
      client.locator('button[aria-label^="Remove URL"]'),
      client.locator('#skip-consent').locator('xpath=..')],
    { margin: 32, minWidth: 900 });
  await client.locator('button:has-text("Save")').last().click();
  await settle(page, 3000);

  // The new client's page.
  // The tab row, with the Back link above it.
  const tabs = page.locator('[role=tablist]').first();
  const back = page.getByText('Back', { exact: true }).first();
  await page.click('[role=tab]:has-text("Credentials")');
  await settle(page, 1500);
  await shot(page, 'pocket-id-credentials',
    [back, tabs, page.locator('button:has-text("Add client secret")')], { margin: 32 });

  await page.click('[role=tab]:has-text("Allowed User Groups")');
  await settle(page, 1500);
  await shot(page, 'pocket-id-allowed-groups',
    [back, tabs, page.locator('[role=tabpanel]:visible button:has-text("Unrestrict")')],
    { margin: 32 });

  await browser.close();
});
