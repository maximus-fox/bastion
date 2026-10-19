// Service-worker behaviour: tracker rules, event storage, per-tab data,
// history, phishing interstitial, settings and TLS status.
import { test, before, after } from 'node:test';
/* global addShieldEvent, handleExfilAlert, handleContentMessage, handlePhishingDetected, phishingBrand */
import assert from 'node:assert/strict';
import { launchExtension, waitFor } from './harness.mjs';

const hits = []; // hosts that reached the fixture server for /pixel*
const SECURE_HEADERS = {
  'strict-transport-security': 'max-age=1', 'content-security-policy': "default-src 'self'",
  'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff',
  'x-xss-protection': '0', 'referrer-policy': 'no-referrer',
};

let ext;

before(async () => {
  const page = (body, headers = {}) => (req, res) => {
    res.writeHead(200, { 'content-type': 'text/html', ...headers });
    res.end(`<!doctype html><body>${typeof body === 'function' ? body(req) : body}</body>`);
  };
  // <img> pointing at a host on this same server
  const img = (host, n) => (req) => `<img src="http://${host}:${req.headers.host.split(':')[1]}/pixel?${n}">`;
  ext = await launchExtension({
    '/pixel': (req, res) => { hits.push(req.headers.host.split(':')[0]); res.end(); },
    '/plain': page('plain'),
    '/third': page((req) => img('counter.yadro.ru', 1)(req) + img('counter.yadro.run', 2)(req)),
    '/first': page(img('counter.yadro.ru', 3)),
    '/trackers': page(img('counter.yadro.ru', 4)),
    '/secure': page('secure', SECURE_HEADERS),
    '/dupes': (req, res) => {
      res.setHeader('content-type', 'text/html');
      res.setHeader('content-security-policy', ["default-src 'self'", "img-src *"]);
      res.setHeader('x-content-type-options', ['nosniff', 'nosniff']);
      res.end('<!doctype html><body>dupes</body>');
    },
  }, { anyHost: true });
  // tracker rules are installed by onInstalled
  await waitFor(() => ext.sw(async () => (await chrome.declarativeNetRequest.getDynamicRules()).length > 0),
    { timeout: 20000 });
});

after(() => ext?.close());

const tabIdOf = (url) => waitFor(() => ext.sw((u) => chrome.tabs.query({ url: u }).then((t) => t[0]?.id), url));
const session = (key) => ext.sw((k) => chrome.storage.session.get(k).then((d) => d[k] || {}), key);

async function openTab(url) {
  const page = await ext.context.newPage();
  await page.goto(url);
  return { page, tabId: await tabIdOf(url) };
}

const blocked = (url, initiator) => ext.sw(async ({ url, initiator }) => {
  const r = await chrome.declarativeNetRequest.testMatchOutcome({ url, initiator, type: 'image', tabId: -1 });
  return r.matchedRules.length > 0;
}, { url, initiator });

test('tracker rules match whole domains, third-party only', async () => {
  const site = 'http://site.test';
  assert.equal(await blocked('http://t.co/x.png', site), true);
  assert.equal(await blocked('http://img.t.co/x.png', site), true);
  assert.equal(await blocked('http://t.com/x.png', site), false);
  assert.equal(await blocked('http://app.linkedin.com/x.png', site), false); // was hit by ||app.link
  assert.equal(await blocked('http://graph.facebook.com/me', site), false); // API, removed
  assert.equal(await blocked('http://challenges.cloudflare.com/turnstile/v0/api.js', site), false);
  assert.equal(await blocked('http://pixel.facebook.com/x.png', site), true);
  assert.equal(await blocked('http://pixel.facebook.com/x.png', 'http://www.facebook.com'), false);
  assert.equal(await blocked('http://www.facebook.com/tr?id=1', site), true);
  assert.equal(await blocked('http://www.facebook.com/translations', site), false);

  const filters = await ext.sw(async () => (await chrome.declarativeNetRequest.getDynamicRules()).map((r) => r.condition.urlFilter));
  assert.equal(new Set(filters).size, filters.length, 'duplicate rules');
});

test('tracker blocking works on the network', async () => {
  hits.length = 0;
  const page = await ext.context.newPage();
  await page.goto(ext.url('/third', 'site.test'));
  await page.goto(ext.url('/first', 'www.yadro.ru'));
  await page.waitForTimeout(500);
  assert.deepEqual(hits.sort(), ['counter.yadro.ru', 'counter.yadro.run']); // 3rd-party .ru blocked, 1st-party loaded
  await page.close();
});

test('quick off→on of blockTrackers leaves the rules on', async () => {
  const count = () => ext.sw(async () => (await chrome.declarativeNetRequest.getDynamicRules()).length);
  const total = await count();
  await ext.sw(async () => {
    chrome.storage.local.set({ blockTrackers: false });
    await chrome.storage.local.set({ blockTrackers: true });
  });
  await new Promise((r) => setTimeout(r, 1000));
  assert.equal(await count(), total);
  await ext.sw(() => chrome.storage.local.set({ blockTrackers: false }));
  await waitFor(async () => (await count()) === 0);
  await ext.sw(() => chrome.storage.local.set({ blockTrackers: true }));
  await waitFor(async () => (await count()) === total);
});

test('30 events in a burst are all stored', async () => {
  await ext.sw(() => Promise.all(Array.from({ length: 30 }, (_, i) => Promise.all([
    addShieldEvent(9001, { action: 'formBlocked', detail: { timestamp: i } }),
    handleExfilAlert({ method: 'fetch', url: 'u' + i }, 9001),
  ]))));
  assert.equal((await session('shieldEvents'))[9001].length, 30);
  assert.equal((await session('exfilAlerts'))[9001].length, 30);
});

test('event details keep only known primitive fields', async () => {
  await ext.sw(() => handleContentMessage(
    { action: 'exfilAlert', detail: { method: 123, url: 'x'.repeat(5000), html: '<img onerror=1>', nested: { a: 1 } } },
    { id: chrome.runtime.id, tab: { id: 9002 }, url: 'http://a.test/' }));
  const [alert] = await waitFor(async () => (await session('exfilAlerts'))[9002]);
  assert.equal(alert.method, '123');
  assert.equal(alert.url.length, 200);
  assert.equal('html' in alert || 'nested' in alert, false);
});

test('notifications are rate-limited per tab and kind', async () => {
  const ids = await ext.sw(async () => {
    for (let i = 0; i < 5; i++) handleContentMessage({ action: 'minerBlocked', detail: {} },
      { id: chrome.runtime.id, tab: { id: 9003 }, url: 'http://a.test/' });
    await new Promise((r) => setTimeout(r, 500));
    return Object.keys(await chrome.notifications.getAll());
  });
  assert.equal(ids.filter((id) => id.startsWith('tg-minerBlocked')).length, 1, ids.join());
});

test('per-tab data is reset when the tab goes to another site', async () => {
  const page = await ext.context.newPage();
  await page.goto(ext.url('/trackers', 'site-a.test'));
  const tabId = await tabIdOf(ext.url('/trackers', 'site-a.test'));
  await ext.sw((id) => addShieldEvent(id, { action: 'formBlocked', detail: {} }), tabId);
  await waitFor(async () => (await session('trackerCounts'))[tabId]?.total > 0, { timeout: 10000 });
  await page.goto(ext.url('/plain', 'site-b.test'));
  await new Promise((r) => setTimeout(r, 2500)); // past the 2 s tracker flush
  assert.equal((await session('trackerCounts'))[tabId], undefined);
  assert.equal((await session('shieldEvents'))[tabId], undefined);
  await page.close();
});

test('history uses the header grade of its own tab', async () => {
  const a = await openTab(ext.url('/secure', 'graded-a.test'));
  const b = await openTab(ext.url('/plain', 'graded-f.test'));
  await new Promise((r) => setTimeout(r, 3000)); // second autoScan runs at 2 s
  const history = await waitFor(() => ext.sw(() => chrome.storage.local.get('history').then((d) => {
    const h = d.history || [];
    return ['graded-a.test', 'graded-f.test'].every((dom) => h.some((e) => e.domain === dom)) && h;
  })), { timeout: 10000 });
  const grade = (d) => history.find((h) => h.domain === d)?.grade;
  assert.equal(grade('graded-a.test'), 'A');
  assert.equal(grade('graded-f.test'), 'F');
  await a.page.close();
  await b.page.close();
});

test('a duplicated security header counts once', async () => {
  const { page, tabId } = await openTab(ext.url('/dupes', 'dupes.test'));
  const hr = await waitFor(async () => (await session('headerResults'))[tabId]);
  assert.deepEqual(hr.found.sort(), ['content-security-policy', 'x-content-type-options']);
  assert.equal(hr.grade, 'C');
  await page.close();
});

test('phishing report sends the tab to the warning page', async () => {
  const url = ext.url('/plain', 'lookalike.test');
  const { page, tabId } = await openTab(url);
  await ext.sw(({ tabId, url }) => handlePhishingDetected(
    { brand: 'PayPal (IDN)', url: 'http://spoofed.example/', domain: 'spoofed.example' },
    { tab: { id: tabId }, frameId: 0, url }), { tabId, url });
  await page.waitForURL(/warning\.html/);
  const tabUrl = page.url();
  const params = new URL(tabUrl).searchParams;
  assert.equal(tabUrl.startsWith(ext.extensionUrl('warning.html')), true);
  assert.equal(params.get('url'), url);
  assert.equal(params.get('domain'), 'lookalike.test');
  assert.equal(params.get('brand'), 'PayPal (IDN)');
  const events = (await session('shieldEvents'))[tabId] || [];
  assert.ok(events.some((e) => e.action === 'phishingDetected' && e.detail.brand === 'PayPal (IDN)'));
  await page.close();
});

test('phishing brand must be a known name', async () => {
  const brands = await ext.sw(() => ['Google', 'Homograph', 'VTB (IDN)', 'PayPal (Punycode)', '<b>x</b>', 'Homograph Attack']
    .map(phishingBrand));
  assert.deepEqual(brands, ['Google', 'Homograph', 'VTB (IDN)', 'Unknown', 'Unknown', 'Unknown']);
});

test('phishing report is ignored for allowlisted domains and subframes', async () => {
  const url = ext.url('/plain', 'allowed.test');
  const { page, tabId } = await openTab(url);
  await ext.sw(async ({ tabId, url }) => {
    await chrome.storage.local.set({ phishingAllowlist: ['allowed.test'] });
    await handlePhishingDetected({ brand: 'Google' }, { tab: { id: tabId }, frameId: 0, url });
    await handlePhishingDetected({ brand: 'Google' }, { tab: { id: tabId }, frameId: 3, url: 'http://frame.test/' });
  }, { tabId, url });
  await new Promise((r) => setTimeout(r, 500));
  assert.equal(page.url(), url);
  await page.close();
});

test('setSettings writes only known boolean settings', async () => {
  const page = await ext.context.newPage();
  await page.goto(ext.extensionUrl('popup.html'));
  const before = await ext.sw(() => chrome.storage.local.get(null));
  await page.evaluate(() => chrome.runtime.sendMessage({
    action: 'setSettings',
    settings: { antiPhishing: false, blockTrackers: 'no', history: [], evil: true },
  }));
  const after = await ext.sw(() => chrome.storage.local.get(null));
  assert.equal(after.antiPhishing, false);
  assert.equal(after.blockTrackers, before.blockTrackers);
  assert.equal('evil' in after, false);
  assert.deepEqual(after.history, before.history);
  await page.evaluate(() => chrome.runtime.sendMessage({ action: 'setSettings', settings: { antiPhishing: true } }));
  await page.close();
});

test('TLS status is never guessed from reported data', async () => {
  const { page, tabId } = await openTab(ext.url('/plain', 'tls.test'));
  const popup = await ext.context.newPage();
  await popup.goto(ext.extensionUrl('popup.html'));
  await waitFor(async () => (await session('quantumResults'))[tabId]);
  await popup.evaluate((tabId) => chrome.runtime.sendMessage({
    action: 'reportSecurityInfo', tabId,
    securityInfo: { keyExchange: 'ECDHE', cipher: 'AES-256-GCM', protocol: 'h2' },
  }), tabId);
  const info = (await session('quantumResults'))[tabId];
  assert.notEqual(info.pqStatus, 'classic');
  assert.notEqual(info.pqStatus, 'pq_safe');
  assert.equal(info.keyExchange, null);
  assert.equal(info.protocol, 'h2');
  await popup.close();
  await page.close();
});
