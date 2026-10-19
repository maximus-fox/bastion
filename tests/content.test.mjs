// content.js: phishing detection, auto-delete, cookie banners, data: iframes,
// robustness on non-HTML documents.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { domainToASCII, domainToUnicode } from 'node:url';
import { ROOT } from './helpers.mjs';
import { launchExtension, waitFor } from './harness.mjs';

// The detector is a pure block of content.js, marked for testing.
function loadDetector() {
  const src = readFileSync(join(ROOT, 'content.js'), 'utf8');
  const start = src.indexOf('// --- phishing detection');
  const end = src.indexOf('// --- end phishing detection ---');
  assert.ok(start >= 0 && end > start, 'phishing detection markers not found in content.js');
  return new Function(`${src.slice(start, end)}; return { detectPhishing, punycodeDecode, getRegistrableDomain };`)();
}

describe('phishing detector', () => {
  const { detectPhishing, punycodeDecode, getRegistrableDomain } = loadDetector();

  test('real brand domains and look-alike words are not flagged', () => {
    const legit = [
      'www.google.co.uk', 'google.de', 'google.com.br', 'chromium.googlesource.com',
      'login.microsoftonline.com', 'hotmail.com', 'outlook.live.com', 'amazon.de', 'amazon.co.uk',
      's3.amazonaws.com', 'bucket.s3.amazonaws.com', 'paypal.me', 'vtb.com', 'online.sberbank.ru',
      'postbank.de', 'firstbank.com', 'applebees.com', 'googleplex.com', 'apple-tree.ru',
      'outlookindia.com', 'google.github.io', 'example.com', 'github.com', 'yandex.ru',
      domainToASCII('сайт.com'), domainToASCII('пример.рф'), domainToASCII('сбербанк.рф'),
      '127.0.0.1', 'localhost',
    ];
    for (const host of legit) assert.equal(detectPhishing(host), null, host);
  });

  test('typosquats, brand-plus-keyword and embedded brand domains are flagged', () => {
    const phishing = {
      'paypal-secure-login.com': 'PayPal', 'secure-paypal.com': 'PayPal', 'paypal.xyz': 'PayPal',
      'paypa1.com': 'PayPal', 'paypallogin2024.com': 'PayPal', 'paypal.com.account-verify.xyz': 'PayPal',
      'paypal-login.github.io': 'PayPal', 'appleid-verify.com': 'Apple', 'g00gle.com': 'Google',
      'gooogle.com': 'Google', 'rnicrosoft.com': 'Microsoft', 'amaz0n-support.net': 'Amazon',
      'tinkoff-bonus.ru': 'Tinkoff/T-Bank', 'sberbank-online.xyz': 'Sberbank',
    };
    for (const [host, brand] of Object.entries(phishing)) assert.equal(detectPhishing(host), brand, host);
  });

  test('IDN homographs are decoded and flagged', () => {
    assert.equal(detectPhishing('xn--pple-43d.com'), 'Apple (IDN)'); // Cyrillic а + pple
    assert.equal(detectPhishing('xn--pypal-4ve.com'), 'PayPal (IDN)');
    assert.equal(detectPhishing('xn--80ak6aa92e.com'), 'Apple (IDN)'); // аррӏе, all Cyrillic
    assert.equal(detectPhishing(domainToASCII('gооgle.com')), 'Google (IDN)'); // Cyrillic о
    assert.equal(detectPhishing(domainToASCII('мойbank.com')), 'Homograph');
  });

  test('punycode decoder matches the platform', () => {
    for (const name of ['сайт.com', 'пример.рф', 'bücher.de', 'аррӏе.com', '例え.jp']) {
      const ascii = domainToASCII(name);
      const decoded = ascii.split('.').map((l) => (l.startsWith('xn--') ? punycodeDecode(l.slice(4)) : l)).join('.');
      assert.equal(decoded, domainToUnicode(ascii), name);
    }
  });

  test('registrable domain respects multi-label suffixes', () => {
    assert.equal(getRegistrableDomain('www.bbc.co.uk'), 'bbc.co.uk');
    assert.equal(getRegistrableDomain('a.b.example.com'), 'example.com');
    assert.equal(getRegistrableDomain('user.github.io'), 'user.github.io');
    assert.equal(getRegistrableDomain('site.com.ua'), 'site.com.ua');
  });
});

describe('content.js in the browser', () => {
  let ext;
  const EXPIRED_JWT = 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ sub: 'u', exp: 1000 })).toString('base64url') + '.c2lnbmF0dXJlc2lnbmF0dXJl';
  const html = (body, head = '') => `<!doctype html><html><head>${head}</head><body>${body}</body></html>`;

  before(async () => {
    ext = await launchExtension({
      '/': html('<p>hello</p>'),
      '/app/page': html('<p>app</p>'),
      '/autodelete': html('<p>x</p>', `<script>
        document.cookie = 'token=${EXPIRED_JWT}; path=/';
        localStorage.setItem('token', 'user-prefs');
        localStorage.setItem('session_jwt', '${EXPIRED_JWT}');
      </script>`),
      '/cookies': html(`
        <div style="height:3000px">top</div>
        <article id="recipe" style="width:600px">
          <p>Grandma's chocolate chip cookies: our site cookies recipe, crispy and soft.</p>
          <button>Continue reading</button>
        </article>
        <form id="signup"><label><input type="checkbox" id="gdpr_consent" required>
          I accept the cookie policy</label><button>Sign up</button></form>
        <div id="banner" style="position:fixed;bottom:0;left:0;width:100%;height:80px;background:#eee">
          We use cookies to improve your experience. <button>Accept all</button>
        </div>`),
      '/modal': html('<p>modal page</p>', '<style>body.modal-open{overflow:hidden}</style><script>document.addEventListener("DOMContentLoaded",()=>document.body.classList.add("modal-open"))</script>'),
      '/style-writes': html('<p>static page</p>', `<script>
        window.__styleWrites = 0;
        new MutationObserver((ms) => { for (const m of ms) {
          const t = m.target.nodeType === 1 ? m.target : m.target.parentNode;
          if (t && t.id === 'tg-cookie-hide') window.__styleWrites++;
          for (const n of m.addedNodes) if (n.id === 'tg-cookie-hide') window.__styleWrites++;
        } }).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
      </script>`),
      '/iframes': html(`<iframe id="data" src="data:text/html,<p>fake login</p>"></iframe>
        <iframe id="img" src="data:image/svg+xml;utf8,&lt;svg xmlns='http://www.w3.org/2000/svg'/&gt;"></iframe>
        <iframe id="png" src="data:image/png;base64,iVBORw0KGgo="></iframe>
        <div id="holder"></div>
        <script>
          const u = URL.createObjectURL(new Blob(['<p>invoice.pdf preview</p>'], { type: 'text/html' }));
          document.getElementById('holder').innerHTML = '<iframe id="blob" src="' + u + '"></iframe>';
        </script>`),
      '/doc.svg': (req, res) => {
        res.writeHead(200, { 'content-type': 'image/svg+xml' });
        res.end('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><text>We use cookies</text></svg>');
      },
    }, { anyHost: true });

    // Record what content.js tells the background, independently of how it reacts
    await ext.sw(() => {
      self.__phish = [];
      chrome.runtime.onMessage.addListener((m, sender) => {
        if (m.action === 'phishingDetected') self.__phish.push({ ...m, from: sender.url });
      });
    });
  });

  after(() => ext?.close());

  const phishReports = (host) => ext.sw((h) => self.__phish.filter((m) => m.domain === h), host);

  test('phishing: real sites get no warning, fakes are reported once', async () => {
    const page = await ext.context.newPage();
    for (const host of ['applebees.com', 'www.google.co.uk', 'paypal-secure-login.com']) {
      await page.goto(ext.url('/', host)).catch(() => {}); // the background may redirect fakes
    }
    await page.waitForTimeout(2500); // past the second autoScan run
    assert.deepEqual(await phishReports('applebees.com'), []);
    assert.deepEqual(await phishReports('www.google.co.uk'), []);
    const fake = await phishReports('paypal-secure-login.com');
    assert.equal(fake.length, 1, JSON.stringify(fake));
    assert.equal(fake[0].brand, 'PayPal');
    await page.close();
  });

  test('phishing: nothing is drawn into the page', async () => {
    const page = await ext.context.newPage();
    // a page the background won't redirect: detection runs, the DOM stays clean
    await ext.sw(() => chrome.storage.local.set({ phishingAllowlist: [] }));
    await page.goto(ext.url('/', 'g00gle.com')).catch(() => {});
    await waitFor(async () => (await phishReports('g00gle.com')).length > 0);
    if (new URL(page.url()).hostname === 'g00gle.com') {
      assert.equal(await page.locator('#tg-phishing-overlay').count(), 0);
    }
    await page.close();
  });

  test('phishing: allowlisted hosts are not reported', async () => {
    await ext.sw(() => chrome.storage.local.set({ phishingAllowlist: ['paypal-login.com'] }));
    const page = await ext.context.newPage();
    await page.goto(ext.url('/', 'paypal-login.com')).catch(() => {});
    await page.waitForTimeout(1500);
    assert.deepEqual(await phishReports('paypal-login.com'), []);
    await ext.sw(() => chrome.storage.local.remove('phishingAllowlist'));
    await page.close();
  });

  test('auto-delete removes expired web-storage JWTs, never same-named keys for cookies', async () => {
    await ext.sw(() => chrome.storage.local.set({ autoDeleteExpired: true }));
    const page = await ext.context.newPage();
    try {
      await page.goto(ext.url('/autodelete'));
      await waitFor(() => page.evaluate(() => localStorage.getItem('session_jwt') === null));
      await page.waitForTimeout(500);
      assert.equal(await page.evaluate(() => localStorage.getItem('token')), 'user-prefs');
    } finally {
      await ext.sw(() => chrome.storage.local.set({ autoDeleteExpired: false }));
      await page.close();
    }
  });

  test('cookie banners: fixed consent banner hidden, page content and forms untouched', async () => {
    const page = await ext.context.newPage();
    await page.goto(ext.url('/cookies'));
    await waitFor(() => page.locator('#banner').isHidden());
    assert.equal(await page.locator('#recipe').isVisible(), true, 'recipe card was hidden');
    assert.equal(await page.locator('#signup').isVisible(), true, 'sign-up form was hidden');
    assert.equal(await page.evaluate(() => getComputedStyle(document.getElementById('gdpr_consent')).display), 'inline-block');
    await page.close();
  });

  test('cookie banners: Bootstrap modal scroll lock is left alone', async () => {
    const page = await ext.context.newPage();
    await page.goto(ext.url('/modal'));
    await page.waitForTimeout(1500);
    assert.equal(await page.evaluate(() => getComputedStyle(document.body).overflow), 'hidden');
    await page.close();
  });

  test('cookie banners: the observer does not retrigger itself', async () => {
    const page = await ext.context.newPage();
    await page.goto(ext.url('/style-writes'));
    await page.waitForTimeout(3000);
    const writes = await page.evaluate(() => window.__styleWrites);
    assert.ok(writes <= 2, `style rewritten ${writes} times in 3 s`);
    await page.close();
  });

  test('iframes: data: documents blocked, blob: and data: images kept', async () => {
    const page = await ext.context.newPage();
    await page.goto(ext.url('/iframes'));
    await waitFor(() => page.evaluate(() => !document.getElementById('data').hasAttribute('src')));
    assert.equal(await page.evaluate(() => document.getElementById('img').hasAttribute('src')), false, 'svg data: is a document');
    assert.equal(await page.evaluate(() => document.getElementById('png').hasAttribute('src')), true);
    assert.equal(await page.evaluate(() => document.getElementById('blob').getAttribute('src')?.startsWith('blob:')), true);
    await page.close();
  });

  test('SVG documents raise no content script errors', async () => {
    const page = await ext.context.newPage();
    const errors = [];
    page.on('console', (m) => { if (m.type() === 'error' && m.text().includes('content.js')) errors.push(m.text()); });
    await page.goto(ext.url('/doc.svg'));
    await page.waitForTimeout(5500);
    assert.deepEqual(errors, []);
    await page.close();
  });

  test('detectTLS reports only the negotiated protocol', async () => {
    const page = await ext.context.newPage();
    await page.goto(ext.url('/'));
    const tabId = await ext.sw((u) => chrome.tabs.query({ url: u }).then((t) => t[0].id), ext.url('/'));
    const info = await ext.sw((id) => chrome.tabs.sendMessage(id, { action: 'detectTLS' }), tabId);
    assert.deepEqual(info, { protocol: 'http/1.1' });
    await page.close();
  });

  test('removing a cookie set on a parent domain or a sub-path works', async () => {
    const page = await ext.context.newPage();
    await page.goto(ext.url('/app/page', 'www.example.com'));
    await page.evaluate(() => {
      document.cookie = 'dom=1; domain=example.com; path=/';
      document.cookie = 'pathc=1; path=/app';
    });
    const tabId = await ext.sw((u) => chrome.tabs.query({ url: u }).then((t) => t[0].id), ext.url('/app/page', 'www.example.com'));
    for (const key of ['dom', 'pathc']) {
      const r = await ext.sw(([id, k]) => chrome.tabs.sendMessage(id, { action: 'removeItem', storage: 'cookie', key: k }), [tabId, key]);
      assert.deepEqual(r, { success: true }, key);
    }
    assert.equal(await page.evaluate(() => document.cookie), '');
    await page.close();
  });
});
