// Loads the unpacked extension in Chromium and checks that it boots:
// service worker starts, popup renders without errors, content scripts run.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { chromium } from 'playwright';
import { ROOT } from './helpers.mjs';

let context, server, extensionId, pageUrl;

before(async () => {
  server = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<!doctype html><title>fixture</title><p>hello</p>');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  pageUrl = `http://127.0.0.1:${server.address().port}/`;

  context = await chromium.launchPersistentContext('', {
    channel: 'chromium', // new headless mode, which supports extensions
    args: [`--disable-extensions-except=${ROOT}`, `--load-extension=${ROOT}`],
  });
  const sw = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  extensionId = new URL(sw.url()).host;
});

after(async () => {
  await context?.close();
  server?.close();
});

test('service worker starts', () => {
  assert.match(extensionId, /^[a-p]{32}$/);
});

test('popup renders without page errors', async () => {
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(`chrome-extension://${extensionId}/popup.html`);
  await page.locator('#tabScanner').waitFor();
  await page.waitForTimeout(500);
  assert.deepEqual(errors, []);
  await page.close();
});

test('content scripts run on a regular page', async () => {
  const page = await context.newPage();
  // Record the settings message content.js (ISOLATED world) posts to injected.js
  await page.addInitScript(() => {
    window.addEventListener('message', (e) => {
      if (e.data?.type === 'TG_SETTINGS') window.__tgSettings = e.data;
    });
  });
  await page.goto(pageUrl);
  const settings = await (await page.waitForFunction(() => window.__tgSettings)).jsonValue();
  assert.equal(typeof settings.antiFingerprint, 'boolean');
  // injected.js (MAIN world) wraps XHR for anti-exfiltration
  const xhrPatched = await page.evaluate(
    () => !Function.prototype.toString.call(XMLHttpRequest.prototype.open).includes('[native code]'),
  );
  assert.ok(xhrPatched, 'injected.js did not patch XMLHttpRequest.prototype.open');
  await page.close();
});
