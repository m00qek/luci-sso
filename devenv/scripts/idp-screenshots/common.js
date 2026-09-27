'use strict';

// Playwright helpers shared by the <idp>.js capture scripts. They run in the
// devenv browser image (see lib.sh `capture`), which trusts the run's CA.
//
// Every shot uses the same viewport, the light colour scheme and a device
// scale factor of 1, and is cropped to the part of the page a step talks
// about. Secrets never reach an image: hide() blanks an input's value before
// the capture.

const { chromium } = require('playwright');

const VIEWPORT = { width: 1280, height: 900 };
const SHOTS = '/shots';

// The page launch() opened, for the failure capture in run().
let current = null;

async function launch({ width = VIEWPORT.width } = {}) {
  const browser = await chromium.launch({
    executablePath: '/usr/bin/chromium-browser',
    args: ['--no-sandbox'],
  });
  const context = await browser.newContext({
    viewport: { ...VIEWPORT, width },
    deviceScaleFactor: 1,
    colorScheme: 'light',
    locale: 'en-US',
    timezoneId: 'UTC',
  });
  context.setDefaultTimeout(30000);
  const page = await context.newPage();
  current = page;
  // Chromium reloads its certificate verifier shortly after start-up, once it
  // has read the NSS database holding the run's CA, and fails the requests in
  // flight then (ERR_CERT_VERIFIER_CHANGED). One throwaway visit lets that
  // happen before the real work.
  await page.goto(`https://${process.env.HOST}/`).catch(() => {});
  await page.waitForTimeout(3000);
  return { browser, context, page };
}

// Waits for the page to settle: network idle (bounded), then a short pause
// for animations.
async function settle(page, ms = 800) {
  try {
    await page.waitForLoadState('networkidle', { timeout: 10000 });
  } catch (e) {
    // Some consoles poll forever; the pause below is enough then.
  }
  await page.waitForTimeout(ms);
}

// Captures the smallest rectangle holding every locator, plus a margin, to
// /shots/<name>.png. The page is not scrolled, since several consoles scroll
// an inner panel under a fixed header: when a locator ends below the viewport,
// the viewport grows to fit it for this capture.
async function shot(page, name, locators, { margin = 16, minWidth = 0 } = {}) {
  const size = page.viewportSize();
  let boxes;
  for (let attempt = 0; attempt < 3; attempt++) {
    await page.waitForTimeout(300);
    boxes = [];
    for (const l of locators) {
      const box = await l.first().boundingBox();
      if (!box) throw new Error(`${name}: an element to capture is not visible`);
      boxes.push(box);
    }
    const bottom = Math.max(...boxes.map((b) => b.y + b.height)) + margin;
    if (bottom <= page.viewportSize().height) break;
    await page.setViewportSize({ width: size.width, height: Math.ceil(bottom) + 40 });
  }
  const x0 = Math.max(0, Math.min(...boxes.map((b) => b.x)) - margin);
  const y0 = Math.max(0, Math.min(...boxes.map((b) => b.y)) - margin);
  let x1 = Math.max(...boxes.map((b) => b.x + b.width)) + margin;
  const y1 = Math.max(...boxes.map((b) => b.y + b.height)) + margin;
  if (x1 - x0 < minWidth) x1 = x0 + minWidth;
  x1 = Math.min(x1, size.width);
  await page.screenshot({
    path: `${SHOTS}/${name}.png`,
    clip: { x: x0, y: y0, width: x1 - x0, height: y1 - y0 },
  });
  await page.setViewportSize(size);
  console.log(`captured ${name}.png`);
}

// Shows each matching input's value as dots, the way a password field does,
// so that a secret in a form never reaches an image. The value itself is not
// touched, so the form still submits it.
async function hide(locator) {
  const n = await locator.count();
  for (let i = 0; i < n; i++) {
    await locator.nth(i).evaluate((el) => {
      el.style.webkitTextSecurity = 'disc';
    });
  }
}

// Runs a capture script. On failure it saves the page as /shots/error.png,
// which the IdP script never publishes, and exits non-zero.
function run(main) {
  main().catch(async (e) => {
    console.error(e);
    if (current) await current.screenshot({ path: `${SHOTS}/error.png` }).catch(() => {});
    process.exit(1);
  });
}

module.exports = { launch, settle, shot, hide, run };
