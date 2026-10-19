// End-to-end anti-phishing flow across content.js, background.js and
// warning.html: lookalike → warning page → "Continue" → site, remembered.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { launchExtension } from './harness.mjs';

let ext;
before(async () => {
  ext = await launchExtension({ '/': '<!doctype html><title>site</title><p>site</p>' }, { anyHost: true });
});
after(() => ext?.close());

test('lookalike domain gets the warning page; Continue is remembered', async () => {
  const page = await ext.context.newPage();
  const site = ext.url('/', 'paypal-secure-login.com');
  await page.goto(site);
  await page.waitForURL(/warning\.html/, { timeout: 10000 });
  const params = new URL(page.url()).searchParams;
  assert.equal(params.get('brand'), 'PayPal');
  assert.equal(params.get('domain'), 'paypal-secure-login.com');
  assert.match(await page.locator('#lead').textContent(), /paypal-secure-login\.com/);

  await page.click('#btnContinue');
  await page.waitForURL(site);
  // the content script checks again on this load; it must not bounce back
  await page.waitForTimeout(1500);
  assert.equal(page.url(), site);
  const { phishingAllowlist } = await ext.sw(() => chrome.storage.local.get('phishingAllowlist'));
  assert.deepEqual(phishingAllowlist, ['paypal-secure-login.com']);
  await page.close();
});

test('punycode lookalike is caught and labelled as IDN', async () => {
  const page = await ext.context.newPage();
  await page.goto(ext.url('/', 'xn--pple-43d.com')); // аpple.com with a Cyrillic "а"
  await page.waitForURL(/warning\.html/, { timeout: 10000 });
  assert.equal(new URL(page.url()).searchParams.get('brand'), 'Apple (IDN)');
  await page.close();
});

test('real brand domains are left alone', async () => {
  const page = await ext.context.newPage();
  for (const host of ['www.google.co.uk', 'login.microsoftonline.com', 'applebees.com']) {
    await page.goto(ext.url('/', host));
    await page.waitForTimeout(1200);
    assert.ok(!page.url().includes('warning.html'), `${host} was sent to the warning page`);
  }
  const events = await ext.sw(async () => {
    const { shieldEvents = {} } = await chrome.storage.session.get('shieldEvents');
    return Object.values(shieldEvents).flat();
  });
  assert.ok(!events.some((e) => e.action === 'phishingDetected' && /google|microsoftonline|applebees/.test(e.detail?.domain)));
  await page.close();
});
