// The settings/event channel between settings-preload.js (ISOLATED) and
// injected.js (MAIN) must be private: the page can't forge settings, can't see
// them, and can't inject protection events.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { launchExtension, waitFor } from './harness.mjs';

// Runs before any other page script. Tries every way the old channel could be
// abused and records whatever the page can observe.
const ATTACKER = `<script>
  window.__seen = [];
  window.addEventListener('message', (e) => window.__seen.push(e.data && e.data.type));
  new MutationObserver((ms) => ms.forEach((m) => window.__seen.push('attr:' + m.attributeName)))
    .observe(document.documentElement, { attributes: true });
  const off = JSON.stringify({ blockDataIframes: false, antiFingerprint: false, blockExfil: false });
  document.documentElement.dataset.tgSettings = off;
  window.postMessage({ type: 'TG_SETTINGS', blockDataIframes: false }, '*');
  document.dispatchEvent(new CustomEvent('bastion:hello', { detail: 'bastion:evil' }));
  document.dispatchEvent(new CustomEvent('bastion:evil:settings', { detail: off }));
</script>`;

const iframeBlocked = () => {
  const f = document.createElement('iframe');
  f.setAttribute('src', 'data:text/html,<p>x</p>');
  return f.getAttribute('src') === null;
};

let ext;

before(async () => {
  ext = await launchExtension({
    '/attack': `<!doctype html><head>${ATTACKER}</head><body>attack</body>`,
    '/plain': '<!doctype html><body>plain</body>',
  });
});

after(() => ext?.close());

test('page cannot disable protections by forging settings', async () => {
  const page = await ext.context.newPage();
  await page.goto(ext.url('/attack'));
  await page.waitForTimeout(500); // let stored settings arrive too
  assert.equal(await page.evaluate(iframeBlocked), true);
  await page.close();
});

test('page never sees the extension configuration', async () => {
  const page = await ext.context.newPage();
  await page.goto(ext.url('/attack'));
  await page.waitForTimeout(500);
  const seen = await page.evaluate(() => window.__seen);
  // only the page's own TG_SETTINGS message and attribute write may show up
  assert.equal(seen.filter((t) => t === 'TG_SETTINGS').length, 1, String(seen));
  assert.equal(seen.filter((t) => t === 'attr:data-tg-settings').length, 1, String(seen));
  await page.close();
});

test('page cannot inject protection events', async () => {
  const page = await ext.context.newPage();
  await page.goto(ext.url('/plain'));
  await page.evaluate(() => {
    for (let i = 0; i < 5; i++) window.postMessage({ type: 'TG_MINER_BLOCK', detail: 'fake' }, '*');
  });
  // a genuine event on the same tab proves the pipeline works
  assert.equal(await page.evaluate(iframeBlocked), true);
  const actions = await waitFor(() => ext.sw(async () => {
    const { shieldEvents = {} } = await chrome.storage.session.get('shieldEvents');
    const all = Object.values(shieldEvents).flat().map((e) => e.action);
    return all.includes('dataIframeBlocked') ? all : null;
  }));
  assert.ok(!actions.includes('minerBlocked'), `forged events stored: ${actions}`);
  await page.close();
});

test('settings changes apply to already open tabs', async () => {
  const page = await ext.context.newPage();
  await page.goto(ext.url('/plain'));
  assert.equal(await page.evaluate(iframeBlocked), true);
  await ext.sw(() => chrome.storage.local.set({ blockDataIframes: false }));
  try {
    await waitFor(async () => !(await page.evaluate(iframeBlocked)));
  } finally {
    await ext.sw(() => chrome.storage.local.set({ blockDataIframes: true }));
  }
  await page.close();
});
