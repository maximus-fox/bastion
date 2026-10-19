// Loads the unpacked extension in Chromium and checks that it boots:
// service worker starts, popup renders without errors, content scripts run.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { launchExtension } from './harness.mjs';

let ext;

before(async () => {
  ext = await launchExtension({ '/': '<!doctype html><title>fixture</title><p>hello</p>' });
});

after(() => ext?.close());

test('service worker starts', () => {
  assert.match(ext.extensionId, /^[a-p]{32}$/);
});

test('popup renders without page errors', async () => {
  const page = await ext.context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(ext.extensionUrl('popup.html'));
  await page.locator('#tabScanner').waitFor();
  await page.waitForTimeout(500);
  assert.deepEqual(errors, []);
  await page.close();
});

test('content scripts run on a regular page', async () => {
  const page = await ext.context.newPage();
  await page.goto(ext.url('/'));
  // injected.js (MAIN world) wraps XHR for anti-exfiltration
  const xhrPatched = await page.evaluate(
    () => !Function.prototype.toString.call(XMLHttpRequest.prototype.open).includes('[native code]'),
  );
  assert.ok(xhrPatched, 'injected.js did not patch XMLHttpRequest.prototype.open');
  // content.js (ISOLATED world) reports its storage scan to the service worker
  const history = await ext.sw(async () => {
    for (let i = 0; i < 50; i++) {
      const { history = [] } = await chrome.storage.local.get('history');
      if (history.length) return history;
      await new Promise((r) => setTimeout(r, 100));
    }
    return [];
  });
  assert.ok(history.length > 0, 'content.js autoScan did not report to background');
  await page.close();
});
