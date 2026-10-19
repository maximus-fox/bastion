// The active audit sends attack payloads, so it must stay on the tab's own
// origin, never submit POST forms or user-entered data, and only run when an
// extension page asks.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { launchExtension } from './harness.mjs';

const requests = [];
let ext, sitePage, extPage, siteTabId;

const FORMS_PAGE = `<!doctype html><body>
  <p>Docs: a "SQL syntax error near MySQL" message means your query is wrong.</p>
  <form id="get" action="/search" method="get">
    <input name="q" value="user typed this"><input name="pw" type="password" value="hunter2">
  </form>
  <form id="post" action="/save" method="post"><input name="title"></form>
</body>`;

before(async () => {
  const log = (req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      requests.push({ method: req.method, host: req.headers.host, url: req.url, body });
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(FORMS_PAGE); // same text for every response: nothing is a new signature
    });
  };
  ext = await launchExtension({ '/page': log, '/search': log, '/save': log, '/elsewhere': log });
  sitePage = await ext.context.newPage();
  await sitePage.goto(ext.url('/page?id=1'));
  siteTabId = await ext.sw((u) => chrome.tabs.query({ url: u }).then((t) => t[0].id), ext.url('/page?id=1'));
  extPage = await ext.context.newPage();
  await extPage.goto(ext.extensionUrl('popup.html'));
});

after(() => ext?.close());

const startAudit = (msg) => extPage.evaluate((m) => chrome.runtime.sendMessage(m), msg);

test('content script never collects passwords or typed values', async () => {
  const audit = await extPage.evaluate((tabId) => chrome.tabs.sendMessage(tabId, { action: 'auditPage' }), siteTabId);
  const inputs = audit.pageForms.flatMap((f) => f.inputs);
  assert.ok(inputs.length > 0);
  assert.ok(!inputs.some((i) => i.type === 'password'), JSON.stringify(inputs));
  assert.ok(!inputs.some((i) => 'value' in i), JSON.stringify(inputs));
});

test('audit stays on the tab origin, skips POST forms and sends no user data', async () => {
  requests.length = 0;
  const origin = new URL(ext.url('/')).origin;
  const result = await startAudit({
    action: 'startActiveAll',
    url: ext.url('/page?id=1'),
    params: [{ key: 'id', value: '1' }],
    tabId: siteTabId,
    forms: [
      { action: `${origin}/search`, method: 'GET', inputs: [
        { name: 'q', type: 'text', value: 'user typed this' },
        { name: 'pw', type: 'password', value: 'hunter2' }] },
      { action: `${origin}/save`, method: 'POST', inputs: [{ name: 'title', type: 'text' }] },
      { action: ext.url('/elsewhere', 'localhost'), method: 'GET', inputs: [{ name: 'x', type: 'text' }] },
    ],
  });
  assert.ok(!result.error, result.error);
  assert.ok(requests.length > 0, 'no requests were made');
  assert.deepEqual(requests.filter((r) => r.method !== 'GET'), []);
  assert.deepEqual(requests.filter((r) => !r.host.startsWith('127.0.0.1')), []);
  const leaked = requests.filter((r) => /hunter2|user%20typed|user\+typed|[?&]pw=/.test(r.url));
  assert.deepEqual(leaked, []);
  assert.ok(requests.some((r) => r.url.startsWith('/search?')), 'GET form was not tested');
  // the SQL error text is on the untouched page too, so it is not a finding
  assert.deepEqual([...result.sqli, ...result.formResults].filter((f) => f.type === 'sqli'), []);
});

test('audit refuses a URL outside the tab origin', async () => {
  requests.length = 0;
  const result = await startAudit({
    action: 'startActiveAll', url: ext.url('/page?id=1', 'localhost'),
    params: [{ key: 'id', value: '1' }], forms: [], tabId: siteTabId,
  });
  assert.equal(result.error, 'origin mismatch');
  assert.equal(requests.length, 0);
});
