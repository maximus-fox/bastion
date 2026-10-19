// Shared Playwright harness: loads the unpacked extension in Chromium and
// serves fixture pages from a local HTTP server.
import { createServer } from 'node:http';
import { chromium } from 'playwright';
import { ROOT } from './helpers.mjs';

/**
 * @param {Record<string, string | ((req, res) => void)>} routes path → HTML or handler
 */
export async function launchExtension(routes = {}) {
  const server = createServer((req, res) => {
    const path = new URL(req.url, 'http://x').pathname;
    const route = routes[path];
    if (typeof route === 'function') return route(req, res);
    res.writeHead(route === undefined ? 404 : 200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(route ?? 'not found');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  const context = await chromium.launchPersistentContext('', {
    channel: 'chromium', // new headless mode, which supports extensions
    args: [`--disable-extensions-except=${ROOT}`, `--load-extension=${ROOT}`],
  });
  const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  const extensionId = new URL(worker.url()).host;

  return {
    context,
    worker,
    extensionId,
    /** URL on the fixture server; use `host` to get a different site (e.g. 'localhost'). */
    url: (path = '/', host = '127.0.0.1') => `http://${host}:${port}${path}`,
    extensionUrl: (path) => `chrome-extension://${extensionId}/${path}`,
    /** Run code in the service worker, e.g. to read or seed chrome.storage. */
    sw: (fn, arg) => worker.evaluate(fn, arg),
    async close() {
      await context.close();
      server.close();
    },
  };
}

/** Poll until fn() returns a truthy value (or throw after timeout ms). */
export async function waitFor(fn, { timeout = 5000, interval = 100 } = {}) {
  const end = Date.now() + timeout;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error('waitFor: timed out');
    await new Promise((r) => setTimeout(r, interval));
  }
}
