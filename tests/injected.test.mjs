// Regression tests for injected.js (MAIN world): protections must not break
// legitimate site behaviour, and must still catch what they are for.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from './helpers.mjs';
import { launchExtension, waitFor } from './harness.mjs';

const beacons = [];
const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type' };

let ext;

before(async () => {
  ext = await launchExtension({
    '/page': '<!doctype html><body><div id="root"></div></body>',
    '/links': `<!doctype html><body>
      <a id="noop" href="javascript:void(0)" onclick="window.__noop = 1">noop</a>
      <a id="postback" href="javascript:window.__nav = 1" onclick="window.__handler = 1">postback</a>
    </body>`,
    '/api': (req, res) => {
      res.writeHead(req.method === 'OPTIONS' ? 204 : 200, cors);
      res.end(req.method === 'OPTIONS' ? '' : 'ok');
    },
    '/beacon': (req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => { beacons.push(body); res.writeHead(204, cors); res.end(); });
    },
    '/img.png': (req, res) => {
      res.writeHead(200, { 'content-type': 'image/png' });
      res.end(readFileSync(join(ROOT, 'icon48.png')));
    },
  });
});

after(() => ext?.close());

async function open(path = '/page') {
  const page = await ext.context.newPage();
  await page.goto(ext.url(path));
  return page;
}

// Second site for cross-origin requests (different host → different base domain)
const cross = (path) => ext.url(path, 'localhost');

async function withSetting(key, value, fn) {
  await ext.sw(([k, v]) => chrome.storage.local.set({ [k]: v }), [key, value]);
  try { return await fn(); } finally {
    await ext.sw((k) => chrome.storage.local.remove(k), key);
  }
}

test('window.open returns a usable window handle', async () => {
  const page = await open();
  const [popup, ok] = await Promise.all([
    ext.context.waitForEvent('page'),
    page.evaluate(() => {
      const w = window.open('/page', '_blank');
      return !!w && w.opener === window;
    }),
  ]);
  assert.equal(ok, true);
  await popup.close();
  await page.close();
});

test('clipboard: consecutive copy buttons write what they were asked to', async () => {
  const page = await open();
  await ext.context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: ext.url('/').slice(0, -1) });
  await page.bringToFront();
  const result = await page.evaluate(async () => {
    await navigator.clipboard.writeText('0x' + 'a'.repeat(40));
    await navigator.clipboard.writeText('0x' + 'b'.repeat(40));
    return navigator.clipboard.readText();
  });
  assert.equal(result, '0x' + 'b'.repeat(40));
  await page.close();
});

test('clipboard: writeText accepts non-strings like the native API', async () => {
  const page = await open();
  await page.bringToFront();
  const result = await page.evaluate(async () => {
    try {
      await navigator.clipboard.writeText(12345);
      return navigator.clipboard.readText();
    } catch (e) { return e.name; }
  });
  assert.equal(result, '12345');
  await page.close();
});

test('clipboard: a swap right after the user copied an address is still blocked', async () => {
  const page = await open();
  await page.bringToFront();
  const result = await page.evaluate(async () => {
    const A = '0x' + 'a'.repeat(40);
    const B = '0x' + 'c'.repeat(40);
    const p = document.createElement('p');
    p.textContent = A;
    document.body.appendChild(p);
    getSelection().selectAllChildren(p);

    // hijack via writeText after the copy
    document.dispatchEvent(new ClipboardEvent('copy', { clipboardData: new DataTransfer() }));
    await navigator.clipboard.writeText(B);
    const viaWriteText = await navigator.clipboard.readText();

    // hijack via clipboardData.setData inside a copy listener
    const dt = new DataTransfer();
    document.addEventListener('copy', (e) => e.clipboardData.setData('text/plain', B), { once: true });
    document.dispatchEvent(new ClipboardEvent('copy', { clipboardData: dt }));
    return { viaWriteText, viaSetData: dt.getData('text/plain') };
  });
  assert.deepEqual(result, { viaWriteText: '0x' + 'a'.repeat(40), viaSetData: '0x' + 'a'.repeat(40) });
  await page.close();
});

test('javascript: links: site click handlers run, no-op hrefs are untouched', async () => {
  await withSetting('blockJavascriptUrls', true, async () => {
    const page = await open('/links');
    await page.click('#postback');
    await page.click('#noop');
    const state = await page.evaluate(() => {
      const a = document.createElement('a');
      a.setAttribute('href', 'javascript:void(0)');
      const b = document.createElement('a');
      b.setAttribute('href', 'javascript:alert(1)');
      return {
        handler: window.__handler, nav: window.__nav, noop: window.__noop,
        noopHref: a.getAttribute('href'), evilHref: b.getAttribute('href'),
      };
    });
    assert.deepEqual(state, {
      handler: 1, nav: undefined, noop: 1, noopHref: 'javascript:void(0)', evilHref: '#',
    });
    await page.close();
  });
});

test('iframes: blob: and inert data: sources load, HTML data: is blocked', async () => {
  const page = await open();
  const srcs = await page.evaluate(() => {
    const blob = URL.createObjectURL(new Blob(['<p>preview</p>'], { type: 'text/html' }));
    const viaAttr = (v) => { const f = document.createElement('iframe'); f.setAttribute('src', v); return f.getAttribute('src'); };
    const viaProp = (v) => { const f = document.createElement('iframe'); f.src = v; return f.getAttribute('src'); };
    return {
      blobAttr: viaAttr(blob) === blob,
      blobProp: viaProp(blob) === blob,
      png: viaAttr('data:image/png;base64,iVBORw0KGgo=') !== null,
      pdf: viaProp('data:application/pdf;base64,JVBERi0=') !== null,
      html: viaAttr('data:text/html,<p>x</p>'),
      bare: viaProp('data:,hello'),
      svg: viaAttr('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"/>'),
    };
  });
  assert.deepEqual(srcs, { blobAttr: true, blobProp: true, png: true, pdf: true, html: null, bare: null, svg: null });
  await page.close();
});

test('keylogger detection never drops the page\'s own key listeners', async () => {
  const page = await open();
  const fired = await page.evaluate(() => {
    let count = 0;
    for (let i = 0; i < 8; i++) {
      const input = document.createElement('input');
      document.body.appendChild(input);
      input.addEventListener('keydown', () => { count++; });
      input.dispatchEvent(new KeyboardEvent('keydown', { key: String(i) }));
    }
    return count;
  });
  assert.equal(fired, 8);
  await page.close();
});

test('WebGL: readPixels is exact and limits never exceed the GPU', async () => {
  const page = await open();
  const r = await page.evaluate(async () => {
    const real = await new Promise((resolve) => {
      const src = `const gl = new OffscreenCanvas(1, 1).getContext('webgl');
        postMessage([gl.MAX_TEXTURE_SIZE, gl.MAX_VERTEX_ATTRIBS, gl.MAX_VERTEX_UNIFORM_VECTORS, gl.MAX_RENDERBUFFER_SIZE]
          .map((p) => gl.getParameter(p)));`;
      const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
      w.onmessage = (e) => resolve(e.data);
    });
    const c = document.createElement('canvas');
    c.width = c.height = 4;
    const gl = c.getContext('webgl');
    gl.clearColor(10 / 255, 20 / 255, 30 / 255, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    const px = new Uint8Array(4);
    gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px);
    const reported = [gl.MAX_TEXTURE_SIZE, gl.MAX_VERTEX_ATTRIBS, gl.MAX_VERTEX_UNIFORM_VECTORS, gl.MAX_RENDERBUFFER_SIZE]
      .map((p) => gl.getParameter(p));
    return { px: [...px], real, reported };
  });
  assert.deepEqual(r.px, [10, 20, 30, 255]);
  r.reported.forEach((v, i) => assert.ok(v <= r.real[i], `param #${i}: reported ${v} > real ${r.real[i]}`));
  await page.close();
});

test('blob: workers are not watched or killed by a CPU heuristic', async () => {
  const page = await open();
  await page.evaluate(() => {
    window.__idleCalls = 0;
    const orig = window.requestIdleCallback;
    window.requestIdleCallback = function () { window.__idleCalls++; return orig.apply(this, arguments); };
    window.__w = new Worker(URL.createObjectURL(new Blob(['onmessage = (e) => postMessage(e.data)'], { type: 'text/javascript' })));
  });
  await page.waitForTimeout(3500); // the old monitor polled every 3 s
  const r = await page.evaluate(() => new Promise((resolve) => {
    window.__w.onmessage = (e) => resolve({ idle: window.__idleCalls, echo: e.data });
    window.__w.postMessage('alive');
  }));
  assert.deepEqual(r, { idle: 0, echo: 'alive' });
  await page.close();
});

test('exfil: legit token use passes, stored token leaving in a URL is blocked', async () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const header = b64({ alg: 'HS256', typ: 'JWT' });
  const token = `${header}.${b64({ sub: 'user-1', exp: 9999999999, scope: 'read write' })}.${'s'.repeat(43)}`;
  const other = `${header}.${b64({ sub: 'someone-else', exp: 9999999999 })}.${'o'.repeat(43)}`;

  const page = await ext.context.newPage();
  const logs = [];
  page.on('console', (m) => { if (m.text().includes('[Bastion]')) logs.push(m.text()); });
  await page.goto(ext.url('/page'));
  await page.evaluate((t) => localStorage.setItem('auth', JSON.stringify({ access_token: t })), token);
  await page.goto(ext.url('/page')); // fresh document so the token cache is cold
  beacons.length = 0;

  const r = await page.evaluate(async ({ token, other, api, beacon }) => {
    const attempt = (p) => p.then(() => 'ok', () => 'blocked');
    return {
      authHeader: await attempt(fetch(api, { headers: { Authorization: `Bearer ${token}` } })),
      sameHeaderOtherToken: await attempt(fetch(`${api}?t=${other}`)),
      tokenInUrl: await attempt(fetch(`${api}?t=${token}`)),
      blobBeacon: navigator.sendBeacon(beacon, new Blob(['metrics=1'], { type: 'text/plain' })),
      tokenBeacon: navigator.sendBeacon(beacon, new Blob([`t=${token}`], { type: 'text/plain' })),
    };
  }, { token, other, api: cross('/api'), beacon: cross('/beacon') });

  assert.deepEqual(r, { authHeader: 'ok', sameHeaderOtherToken: 'ok', tokenInUrl: 'blocked', blobBeacon: true, tokenBeacon: true });
  await waitFor(() => beacons.includes('metrics=1'));
  await page.waitForTimeout(300);
  assert.ok(!beacons.some((b) => b.includes(token)), 'beacon carrying the stored token was sent');
  assert.deepEqual(logs, []);
  await page.close();
});

test('anti-fingerprint toggles apply live and return real values when off', async () => {
  const page = await open();
  assert.equal(await page.evaluate(() => screen.width), 1920);
  await withSetting('antiFingerprint', false, async () => {
    await waitFor(async () => (await page.evaluate(() => screen.width)) !== 1920);
    const r = await page.evaluate(() => new Promise((resolve) => {
      const w = new Worker(URL.createObjectURL(new Blob(['postMessage(navigator.hardwareConcurrency)'], { type: 'text/javascript' })));
      w.onmessage = (e) => resolve({ main: navigator.hardwareConcurrency, worker: e.data });
    }));
    assert.equal(r.main, r.worker);
  });
  await waitFor(async () => (await page.evaluate(() => screen.width)) === 1920);
  await page.close();
});

test('canvas noise is stable and never modifies the page\'s canvas', async () => {
  const page = await open();
  const r = await page.evaluate(async (crossImg) => {
    const c = document.createElement('canvas');
    c.width = 60;
    c.height = 20;
    const ctx = c.getContext('2d');
    ctx.fillStyle = '#f60';
    ctx.fillRect(0, 0, 60, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Bastion', 2, 15);
    const before = Array.from(ctx.getImageData(0, 0, 60, 20).data).join();
    const a = c.toDataURL();
    const b = c.toDataURL();
    const after = Array.from(ctx.getImageData(0, 0, 60, 20).data).join();

    // a failed export of a tainted canvas must not switch the noise off
    const img = new Image();
    await new Promise((res) => { img.onload = res; img.src = crossImg; });
    const tainted = document.createElement('canvas');
    tainted.getContext('2d').drawImage(img, 0, 0);
    try { tainted.toDataURL(); } catch { /* SecurityError, as natively */ }
    const solid = document.createElement('canvas');
    solid.width = solid.height = 2;
    const sctx = solid.getContext('2d');
    sctx.fillStyle = '#f00';
    sctx.fillRect(0, 0, 2, 2);
    const firstPixel = Array.from(sctx.getImageData(0, 0, 1, 1).data);
    return { stable: a === b, untouched: before === after, noised: firstPixel.join() !== '255,0,0,255' };
  }, cross('/img.png'));
  assert.deepEqual(r, { stable: true, untouched: true, noised: true });
  await page.close();
});

test('wrapped constructors keep native contracts', async () => {
  const page = await open();
  const r = await page.evaluate(() => {
    const out = {};
    out.eventSourceConsts = [EventSource.CONNECTING, EventSource.OPEN, EventSource.CLOSED].join();
    try {
      const pc = new RTCPeerConnection(Object.freeze({ iceServers: Object.freeze([Object.freeze({ urls: 'stun:stun.example.org' })]) }));
      pc.close();
      out.frozenRtc = 'ok';
    } catch (e) { out.frozenRtc = e.name; }
    try { document.body.setAttribute('1bad', 'x'); out.badAttr = 'swallowed'; } catch (e) { out.badAttr = e.name; }
    class MySocket extends WebSocket { hello() { return 'hi'; } }
    const ws = new MySocket('ws://127.0.0.1:9');
    out.subclass = typeof ws.hello === 'function' && ws.hello();
    ws.close();
    try { Worker('x.js'); out.workerWithoutNew = 'allowed'; } catch (e) { out.workerWithoutNew = e.name; }
    return out;
  });
  assert.deepEqual(r, {
    eventSourceConsts: '0,1,2', frozenRtc: 'ok', badAttr: 'InvalidCharacterError',
    subclass: 'hi', workerWithoutNew: 'TypeError',
  });
  await ext.context.grantPermissions(['notifications'], { origin: ext.url('/').slice(0, -1) });
  assert.equal(await page.evaluate(() => Notification.permission), 'granted');
  await page.close();
});
