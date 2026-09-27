'use strict';

// Keycloak admin console steps of docs/how-to/providers/keycloak.md. Run by
// keycloak.sh; see common.js for the capture rules.
//
//   keycloak-capability-config.png  Create client, Capability config, with
//                                   Client authentication on
//   keycloak-login-settings.png     Create client, Login settings, with the
//                                   redirect and post logout redirect URIs
//   keycloak-dedicated-scope.png    the client's dedicated scope before any
//                                   mapper: "Configure a new mapper"
//   keycloak-group-mapper.png       the Group Membership mapper form, filled

const { launch, settle, shot, run } = require('./common');

const KC = `https://${process.env.HOST}`;
const PASSWORD = process.env.ADMIN_PASSWORD;
const REALM = 'home';
const CLIENT = 'luci-router';
const ROUTER = 'https://router.example.com';

// Creates the realm through the admin REST API: the guide starts from an
// existing realm.
async function createRealm() {
  const res = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: PASSWORD,
    }),
  });
  const { access_token: token } = await res.json();
  const created = await fetch(`${KC}/admin/realms`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ realm: REALM, enabled: true }),
  });
  if (created.status !== 201) throw new Error(`realm creation: HTTP ${created.status}`);
}

// Closes the "… successfully" toasts, which would cover part of a capture.
async function closeToasts(page) {
  const buttons = page.locator('.pf-v5-c-alert-group button[aria-label^="Close"]');
  while (await buttons.count()) {
    await buttons.first().click();
    await page.waitForTimeout(200);
  }
}

run(async () => {
  await createRealm();
  const { browser, page } = await launch();

  await page.goto(`${KC}/admin/master/console/`);
  await settle(page);
  await page.fill('#username', 'admin');
  await page.fill('#password', PASSWORD);
  await page.click('#kc-login');
  await settle(page, 2000);

  // Manage realms > home, then Clients > Create client.
  await page.click('#nav-item-realms');
  await settle(page);
  await page.click(`a:text-is("${REALM}")`);
  await settle(page, 1500);
  await page.click('#nav-item-clients');
  await settle(page);
  await page.click('a:has-text("Create client"), button:has-text("Create client")');
  await settle(page);

  await page.fill('#clientId', CLIENT);
  await page.click('button:has-text("Next")');
  await settle(page);

  await page.locator('#kc-authentication').check({ force: true });
  await settle(page, 500);
  await shot(page, 'keycloak-capability-config',
    [page.locator('.pf-v5-c-wizard__nav'), page.locator('#kc-authentication'),
      page.locator('text="Require DPoP bound tokens"')],
    { minWidth: 900 });

  await page.click('button:has-text("Next")');
  await settle(page);
  await page.fill('[data-testid="redirectUris0"]', `${ROUTER}/cgi-bin/luci-sso/callback`);
  await page.fill('[data-testid="attributes.post🍺logout🍺redirect🍺uris0"]', `${ROUTER}/`);
  await page.locator('body').click({ position: { x: 5, y: 890 } });
  await settle(page, 500);
  await shot(page, 'keycloak-login-settings',
    [page.locator('.pf-v5-c-wizard__nav'),
      page.locator('form').filter({ has: page.locator('[data-testid="redirectUris0"]') })]);

  await page.click('button:has-text("Save")');
  await settle(page, 2000);
  await closeToasts(page);

  // Client scopes tab > luci-router-dedicated, which has no mapper yet.
  await page.click('[data-testid="clientScopesTab"], button:has-text("Client scopes")');
  await settle(page, 1500);
  await page.click(`a:has-text("${CLIENT}-dedicated")`);
  await settle(page, 1500);
  await closeToasts(page);
  await shot(page, 'keycloak-dedicated-scope',
    [page.locator(`h1:has-text("${CLIENT}-dedicated")`),
      page.locator('[data-testid="configure-a-new-mapper-empty-action"]')],
    { minWidth: 960 });

  await page.click('[data-testid="configure-a-new-mapper-empty-action"]');
  await settle(page);
  await page.click('text="Group Membership"');
  await settle(page, 1500);
  await page.fill('#name', 'groups');
  await page.fill('[id="config.claim🍺name"]', 'groups');
  await page.locator('[id="full.path"]').uncheck({ force: true });
  await settle(page, 500);
  await closeToasts(page);
  await shot(page, 'keycloak-group-mapper',
    [page.locator('h1:has-text("Add mapper")'),
      page.locator('form').filter({ has: page.locator('#name') })]);

  await browser.close();
});
