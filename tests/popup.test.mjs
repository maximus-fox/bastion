// Popup and phishing warning page: data that came from web pages must never
// break rendering or the layout, the TLS tab shows only what Chrome exposes,
// and the warning page treats its URL parameters as untrusted text.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from './helpers.mjs';
import { launchExtension } from './harness.mjs';

let ext;
before(async () => { ext = await launchExtension({ '/': '<!doctype html><p>target</p>' }); });
after(() => ext?.close());

const LONG_URL = 'https://evil.example/' + 'x'.repeat(1500);
const FINDING = { key: 'token', storage: 'localStorage', type: 'api_key', severity: 'critical', label: 'API key', token: 'sk-test' };

/**
 * Open the popup as if it were opened on a tab with `url`. chrome.tabs.* and
 * selected background requests are answered from the given tables, everything
 * else goes to the real service worker.
 */
async function openPopup({ url = 'https://example.com/', tabResponses = {}, bgResponses = {}, uiLang = null, width } = {}) {
  const page = await ext.context.newPage();
  if (width) await page.setViewportSize({ width, height: 800 });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.addInitScript(({ url, tabResponses, bgResponses, uiLang }) => {
    window.__tabCalls = [];
    const tab = { id: 4242, url, active: true };
    const reply = (cb, value) => setTimeout(() => cb && cb(value));
    chrome.tabs.query = (q, cb) => reply(cb, [tab]);
    chrome.tabs.get = (id, cb) => reply(cb, tab);
    chrome.tabs.sendMessage = (id, msg, cb) => {
      window.__tabCalls.push(msg);
      reply(cb, tabResponses[msg.action]);
    };
    const realSend = chrome.runtime.sendMessage.bind(chrome.runtime);
    chrome.runtime.sendMessage = (msg, cb) => (msg && msg.action in bgResponses
      ? reply(cb, bgResponses[msg.action])
      : realSend(msg, cb));
    if (uiLang) chrome.i18n.getUILanguage = () => uiLang;
  }, { url, tabResponses, bgResponses, uiLang });
  await ext.sw(() => chrome.storage.local.remove('lang'));
  await page.goto(ext.extensionUrl('popup.html'));
  await page.locator('#scannerContent .status').first().waitFor();
  return { page, errors };
}

const PAGE_DATA = {
  // a page can make these fields any type it likes
  getExfilAlerts: [
    { method: 123, url: LONG_URL, blocked: true },
    { url: null, blocked: true },
    { method: 'POST', url: { nested: true }, blocked: false },
  ],
  getShieldEvents: [
    { action: 'jsUrlBlocked', timestamp: Date.now() },
    { action: 'dataIframeBlocked', timestamp: 'not a date' },
    { action: 'somethingNew' },
  ],
  getAutoDeleteLog: [{ key: { o: 1 }, domain: 5, timestamp: Date.now() }, { key: 'k'.repeat(800), domain: 'd' }],
};

test('alerts and events with non-string fields do not break rendering', async () => {
  const { page, errors } = await openPopup({ tabResponses: { scan: { findings: [FINDING], url: 'https://example.com/' } }, bgResponses: PAGE_DATA });
  await page.locator('#scannerContent .exfil-item').first().waitFor();
  assert.match(await page.locator('#scannerContent .exfil-section').innerText(), /123/);
  await page.click('#tabProtect');
  await page.locator('#protectContent .protect-log-item').first().waitFor();
  await page.waitForTimeout(300);
  const protect = await page.locator('#protectContent').innerText();
  assert.match(protect, /123 → https:\/\/evil\.example/);
  // known actions get a label, unknown ones a generic one — never the raw key
  assert.doesNotMatch(protect, /jsUrlBlocked|dataIframeBlocked|somethingNew|eventOther/);
  assert.deepEqual(errors, []);
  await page.close();
});

test('TLS tab reports only what Chrome exposes', async () => {
  const { page, errors } = await openPopup({ tabResponses: { detectTLS: { protocol: 'h2' } } });
  await page.click('#tabQuantum');
  const text = await page.locator('#quantumContent').innerText();
  assert.match(text, /HTTP\/2/);
  assert.doesNotMatch(text, /ECDHE|AES-256|TLS 1\.3|Classic|Классическ|Detecting|Определение/i);
  assert.notEqual((await page.locator('.quantum-grade').innerText()).trim(), 'C');
  assert.deepEqual(errors, []);
  await page.close();
});

test('no-access screen does not advise a reload where it cannot help', async () => {
  const { page } = await openPopup({ url: 'https://chromewebstore.google.com/detail/x', uiLang: 'en-US' });
  const status = page.locator('#scannerContent .status');
  assert.match(await status.innerText(), /does not allow extensions/);
  assert.equal(await status.evaluate((el) => el.classList.contains('safe')), false);
  await page.close();
});

test('language defaults to the browser UI language', async () => {
  for (const [uiLang, expected] of [['ru-RU', 'ru'], ['en-GB', 'en']]) {
    const { page } = await openPopup({ uiLang });
    assert.equal(await page.evaluate(() => document.documentElement.lang), expected);
    assert.equal((await page.locator('#langBtn').innerText()).trim(), expected.toUpperCase());
    await page.close();
  }
});

test('deleting a finding asks first and reports a failed delete', async () => {
  const { page } = await openPopup({
    uiLang: 'en-US',
    tabResponses: {
      scan: { findings: [FINDING], url: 'https://example.com/' },
      removeItem: { success: false, error: 'cookie is still set' },
    },
  });
  await page.click('#scannerContent .btn-delete');
  assert.equal(await page.evaluate(() => window.__tabCalls.some((m) => m.action === 'removeItem')), false);
  await page.click('#scannerContent .btn-delete-yes');
  await page.waitForFunction(() => document.getElementById('toast').textContent.includes('cookie is still set'));
  await page.close();
});

test('page-controlled strings never widen the 440px popup', async () => {
  const { page } = await openPopup({
    width: 440,
    tabResponses: {
      scan: { findings: [{ ...FINDING, key: 'k'.repeat(600) }], url: LONG_URL },
      auditPage: {
        findings: [{ type: 'xss', subtype: 'reflected_param', severity: 'warning', detail: 'y'.repeat(600), url: LONG_URL, param: 'p'.repeat(300) }],
        urlParams: [], pageForms: [], url: LONG_URL,
      },
    },
    bgResponses: {
      ...PAGE_DATA,
      getExfilAlerts: [{ method: 'GET', url: LONG_URL, blocked: true }],
    },
  });
  for (const tab of ['Scanner', 'Audit', 'Protect']) {
    await page.click(`#tab${tab}`);
    await page.waitForTimeout(400);
    const width = await page.evaluate(() => document.documentElement.scrollWidth);
    assert.ok(width <= 440, `${tab} tab is ${width}px wide`);
  }
  await page.close();
});

test('tabs are keyboard accessible', async () => {
  const { page } = await openPopup();
  await page.focus('#tabScanner');
  await page.keyboard.press('ArrowRight');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'tabHeaders');
  assert.equal(await page.getAttribute('#tabHeaders', 'aria-selected'), 'true');
  assert.equal(await page.evaluate(() => document.getElementById('tab-headers').classList.contains('active')), true);
  await page.keyboard.press('End');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'tabProtect');
  await page.close();
});

// --- warning.html ---

const warningUrl = (p) => ext.extensionUrl('warning.html?' + new URLSearchParams(p));
const allowlist = () => ext.sw(async () => (await chrome.storage.local.get({ phishingAllowlist: [] })).phishingAllowlist);

test('warning page renders its parameters as text', async () => {
  const page = await ext.context.newPage();
  const html = '<img src=x onerror="window.__pwned=1">';
  await page.goto(warningUrl({ url: 'https://evil.test/', domain: html, brand: html }));
  assert.match(await page.locator('#lead').innerText(), /<img src=x/);
  assert.equal(await page.locator('img').count(), 0);
  assert.equal(await page.evaluate(() => window.__pwned), undefined);
  await page.close();
});

test('continuing remembers the site and opens it', async () => {
  await ext.sw(() => chrome.storage.local.set({ phishingAllowlist: ['127.0.0.1', 'other.test'] }));
  const page = await ext.context.newPage();
  const target = ext.url('/');
  await page.goto(warningUrl({ url: target, domain: '127.0.0.1', brand: 'PayPal' }));
  await page.click('#btnContinue');
  await page.waitForURL(target);
  assert.deepEqual(await allowlist(), ['other.test', '127.0.0.1']);
  await page.close();
});

test('continuing refuses non-http URLs and other hosts', async () => {
  await ext.sw(() => chrome.storage.local.set({ phishingAllowlist: [] }));
  for (const p of [
    { url: 'javascript:alert(1)', domain: '', brand: 'X' },
    { url: ext.url('/', 'localhost'), domain: '127.0.0.1', brand: 'X' },
  ]) {
    const page = await ext.context.newPage();
    const start = warningUrl(p);
    await page.goto(start);
    await page.click('#btnContinue');
    await page.locator('#error').waitFor({ state: 'visible' });
    assert.equal(page.url(), start);
    await page.close();
  }
  assert.deepEqual(await allowlist(), []);
});

test('"back to safety" never returns to the flagged page', async () => {
  const page = await ext.context.newPage();
  await page.goto(warningUrl({ url: 'https://evil.test/', domain: 'evil.test', brand: 'X' }));
  await page.click('#btnBack');
  await page.waitForURL(/^chrome:\/\/new-tab-page/);
  await page.close();
});

// --- i18n ---

test('i18n: locales match and every referenced key exists', () => {
  const src = (f) => readFileSync(join(ROOT, f), 'utf8');
  const LANGS = new Function(`${src('i18n.js')}; return LANGS;`)();
  const ru = Object.keys(LANGS.ru).sort();
  const en = Object.keys(LANGS.en).sort();
  assert.deepEqual(ru, en);

  const used = new Set();
  for (const f of ['popup.js', 'warning.js', 'i18n.js'].filter((f) => existsSync(join(ROOT, f)))) {
    for (const [, k] of src(f).matchAll(/\bt\('(\w+)'\)/g)) used.add(k);
    for (const [, k] of src(f).matchAll(/(?:labelKey|descKey|onKey|offKey): '(\w+)'/g)) used.add(k);
  }
  for (const n of ['Scanner', 'Headers', 'History', 'Quantum', 'Protect', 'Audit']) used.add('tab' + n);
  assert.deepEqual([...used].filter((k) => !(k in LANGS.ru)), []);
});

test('every protection event has a label', () => {
  const popup = readFileSync(join(ROOT, 'popup.js'), 'utf8');
  const block = popup.slice(popup.indexOf('const EVENT_LABELS'), popup.indexOf('};', popup.indexOf('const EVENT_LABELS')));
  const labelled = new Set([...block.matchAll(/'(\w+)': \{/g)].map((m) => m[1]));
  const actions = ['phishingDetected', 'formBlocked', 'minerBlocked', 'fingerprintDetected', 'cookieBannerHidden',
    'webrtcBlocked', 'keyloggerDetected', 'tabNappingBlocked', 'clipboardSwapBlocked', 'jsThreatFound',
    'darkPatternFound', 'jsUrlBlocked', 'dataIframeBlocked'];
  const bridge = readFileSync(join(ROOT, 'settings-preload.js'), 'utf8');
  // exfilAlert has its own log (exfil alerts), the rest go to the events log
  for (const [, a] of bridge.matchAll(/TG_\w+: '(\w+)'/g)) if (a !== 'exfilAlert') actions.push(a);
  assert.deepEqual([...new Set(actions)].filter((a) => !labelled.has(a)), []);
});
