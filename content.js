/**
 * Bastion — Content Script (ISOLATED world)
 * Storage scanner, anti-phishing detection, cookie banners, page audit
 */

// =============================================
// SCANNER
// =============================================
const SECRET_PATTERNS = [
  { name: 'OpenAI API Key', pattern: /^sk-[A-Za-z0-9]{20,}$/, severity: 'critical' },
  { name: 'Stripe Live Key', pattern: /^pk_live_[A-Za-z0-9]{20,}$/, severity: 'critical' },
  { name: 'Stripe Test Key', pattern: /^pk_test_[A-Za-z0-9]{20,}$/, severity: 'warning' },
  { name: 'AWS Access Key', pattern: /^AKIA[A-Z0-9]{16}$/, severity: 'critical' },
  { name: 'GitHub Token', pattern: /^gh[ps]_[A-Za-z0-9]{36,}$/, severity: 'critical' },
  { name: 'GitHub OAuth', pattern: /^gho_[A-Za-z0-9]{36,}$/, severity: 'critical' },
  { name: 'GitLab Token', pattern: /^glpat-[A-Za-z0-9_-]{20,}$/, severity: 'critical' },
];

const PASSWORD_KEYS = /(?:password|passwd|secret|api_?key|apikey|token|auth)/i;
const EMAIL_PATTERN = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const CARD_PATTERN = /^\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}$/;

function isJWT(value) {
  if (!value || typeof value !== 'string') return false;
  const parts = value.split('.');
  if (parts.length !== 3 || !parts[0].startsWith('eyJ')) return false;
  try { JSON.parse(atob(parts[1])); return true; } catch { return false; }
}

function decodeJWT(token) {
  try { return JSON.parse(atob(token.split('.')[1])); } catch { return null; }
}

function scanStorage() {
  const findings = [];
  function scanStore(storage, storageName) {
    try {
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        const value = storage.getItem(key);
        if (!value) continue;

        if (isJWT(value)) {
          const payload = decodeJWT(value);
          findings.push({ type: 'jwt', severity: 'critical', label: 'JWT Token', storage: storageName, key,
            token: value.substring(0, 50) + '...', payload,
            expired: payload && payload.exp ? (payload.exp * 1000 < Date.now()) : null });
          continue;
        }
        for (const sp of SECRET_PATTERNS) {
          if (sp.pattern.test(value)) {
            findings.push({ type: 'api_key', severity: sp.severity, label: sp.name, storage: storageName, key,
              token: value.substring(0, 12) + '***', payload: null, expired: null });
            break;
          }
        }
        if (PASSWORD_KEYS.test(key) && !isJWT(value) && value.length > 8) {
          if (!findings.some(f => f.key === key && f.storage === storageName)) {
            findings.push({ type: 'password', severity: 'warning', label: 'Password / Secret', storage: storageName, key,
              token: value.substring(0, 4) + '****', payload: null, expired: null });
          }
        }
        if (EMAIL_PATTERN.test(value)) {
          findings.push({ type: 'email', severity: 'info', label: 'Email', storage: storageName, key,
            token: value, payload: null, expired: null });
        }
        if (CARD_PATTERN.test(value.trim())) {
          findings.push({ type: 'card', severity: 'critical', label: 'Card Number', storage: storageName, key,
            token: value.replace(/\d(?=.{4})/g, '*'), payload: null, expired: null });
        }
      }
    } catch {}
  }
  scanStore(localStorage, 'localStorage');
  scanStore(sessionStorage, 'sessionStorage');

  // Scan document.cookie for tokens/secrets
  try {
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const eqIdx = cookie.indexOf('=');
      if (eqIdx === -1) continue;
      const key = cookie.substring(0, eqIdx).trim();
      const value = cookie.substring(eqIdx + 1).trim();
      if (!value) continue;

      if (isJWT(value)) {
        const payload = decodeJWT(value);
        findings.push({ type: 'jwt', severity: 'critical', label: 'JWT in Cookie', storage: 'cookie', key,
          token: value.substring(0, 50) + '...', payload,
          expired: payload && payload.exp ? (payload.exp * 1000 < Date.now()) : null });
      }
      for (const sp of SECRET_PATTERNS) {
        if (sp.pattern.test(value)) {
          findings.push({ type: 'api_key', severity: sp.severity, label: sp.name + ' (cookie)', storage: 'cookie', key,
            token: value.substring(0, 12) + '***', payload: null, expired: null });
          break;
        }
      }
    }
  } catch {}

  return findings;
}

function autoDeleteExpired(findings) {
  const deleted = [];
  for (const f of findings) {
    // Web storage only: a cookie JWT shares its name with unrelated localStorage keys
    if (f.type !== 'jwt' || f.expired !== true) continue;
    if (f.storage !== 'localStorage' && f.storage !== 'sessionStorage') continue;
    try {
      const store = f.storage === 'sessionStorage' ? sessionStorage : localStorage;
      if (store.getItem(f.key) === null) continue;
      store.removeItem(f.key);
      deleted.push({ key: f.key, storage: f.storage });
    } catch {}
  }
  if (deleted.length > 0) {
    chrome.runtime.sendMessage({ action: 'autoDeletedExpired', deleted, url: location.href }).catch(() => {});
  }
  return deleted;
}

// =============================================
// ANTI-PHISHING — проверка домена
// =============================================
// --- phishing detection: pure functions, unit-tested in tests/content.test.mjs ---

// Multi-label public suffixes: ccTLD second levels plus hosting platforms where
// every subdomain has a different owner. A compact subset of the Public Suffix List.
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'gov.uk', 'ac.uk', 'nhs.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'co.kr', 'or.kr', 'go.kr',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'com.hk', 'com.tw', 'com.sg', 'com.my',
  'com.ph', 'com.vn', 'co.th', 'in.th', 'co.id', 'or.id', 'co.in', 'net.in', 'org.in',
  'gov.in', 'ac.in', 'com.pk', 'com.bd', 'com.np', 'com.lk',
  'com.br', 'net.br', 'org.br', 'gov.br', 'com.ar', 'com.mx', 'org.mx', 'gob.mx',
  'com.co', 'com.pe', 'com.ve', 'com.uy', 'com.ec',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'com.ua', 'org.ua', 'net.ua', 'gov.ua',
  'com.by', 'com.kz', 'org.kz', 'co.il', 'org.il', 'ac.il', 'gov.il',
  'com.sa', 'com.eg', 'com.ng', 'co.za', 'org.za', 'co.ke', 'com.gh',
  'com.pl', 'net.pl', 'org.pl', 'co.at', 'or.at', 'com.es', 'org.es', 'com.pt',
  'com.gr', 'com.cy', 'co.hu', 'com.ro', 'co.rs',
  'msk.ru', 'spb.ru', 'com.ru', 'net.ru', 'org.ru',
  'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'vercel.app', 'netlify.app',
  'herokuapp.com', 'web.app', 'firebaseapp.com', 'appspot.com', 'blogspot.com',
  'azurewebsites.net', 'cloudfront.net', 's3.amazonaws.com', 'glitch.me',
  'repl.co', 'onrender.com', 'fly.dev', 'wixsite.com', 'weebly.com', 'myshopify.com',
]);

function getRegistrableDomain(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (/^[\d.]+$/.test(host) || host.includes(':')) return host; // IPv4 / IPv6
  const parts = host.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    if (MULTI_LABEL_SUFFIXES.has(parts.slice(i).join('.'))) return parts.slice(i - 1).join('.');
  }
  return parts.slice(-2).join('.');
}

// RFC 3492 decoder for one "xn--" label (without the prefix).
function punycodeDecode(input) {
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const output = [];
  let n = 128, i = 0, bias = 72;
  const basic = Math.max(input.lastIndexOf('-'), 0);
  for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (idx >= input.length) throw new RangeError('bad punycode');
      const c = input.charCodeAt(idx++);
      const digit = c - 48 >>> 0 < 10 ? c - 22 : c - 65 >>> 0 < 26 ? c - 65 : c - 97 >>> 0 < 26 ? c - 97 : base;
      if (digit >= base) throw new RangeError('bad punycode');
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const out = output.length + 1;
    let delta = oldi === 0 ? Math.floor((i - oldi) / damp) : (i - oldi) >> 1;
    delta += Math.floor(delta / out);
    let k = 0;
    for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
    bias = Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    n += Math.floor(i / out);
    i %= out;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

function decodeLabel(label) {
  if (!label.startsWith('xn--')) return label;
  try { return punycodeDecode(label.slice(4)); } catch { return label; }
}

// Cyrillic / Greek letters that render like Latin ones
const CONFUSABLES = {
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'п': 'n',
  'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ь': 'b', 'і': 'i', 'ї': 'i', 'ј': 'j',
  'ԁ': 'd', 'ӏ': 'l', 'ѕ': 's', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w', 'ү': 'y', 'ɡ': 'g',
  'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p',
  'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
};
const NON_LATIN_LETTER = /[Ͱ-ϿЀ-ӿԀ-ԯ]/;

// Digit and letter-pair lookalikes. 'skeleton' keeps length-ish structure for
// prefix checks, 'squash' also folds repeats (gooogle → gogle).
function skeleton(s) {
  return s.toLowerCase().replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o')
    .replace(/[1i|!]/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's')
    .replace(/7/g, 't').replace(/8/g, 'b');
}
function squash(s) {
  return skeleton(s).replace(/(.)\1+/g, '$1');
}

const PHISH_WORDS = ['login', 'logon', 'signin', 'secure', 'security', 'verify', 'verification',
  'account', 'accounts', 'support', 'update', 'wallet', 'auth', 'help', 'service', 'services',
  'online', 'id', 'bonus', 'gift', 'pay', 'bank', 'confirm', 'recovery', 'unlock'];

// True when s is made only of phishing words (e.g. "idverify", "securelogin").
function isPhishWords(s, words) {
  if (!s) return false;
  const ok = [true];
  for (let i = 0; i < s.length; i++) {
    if (!ok[i]) continue;
    for (const w of words) if (s.startsWith(w, i)) ok[i + w.length] = true;
  }
  return !!ok[s.length];
}
const PHISH_WORDS_SKEL = PHISH_WORDS.map(skeleton);

// cc: brand labels that are legitimate on any country TLD (google.de, amazon.co.uk).
// common: dictionary words; "apple-tree.ru" is only suspicious next to a phishing word.
const BRANDS = [
  { brand: 'Google', names: ['google', 'gmail', 'youtube'], cc: ['google', 'youtube'],
    legit: ['google.com', 'gmail.com', 'youtube.com', 'youtu.be', 'googleapis.com', 'withgoogle.com',
      'gstatic.com', 'googlevideo.com', 'googlesource.com', 'googleusercontent.com', 'google.dev',
      'google.ai', 'google-analytics.com', 'youtube-nocookie.com', 'google.github.io'] },
  { brand: 'Apple', names: ['apple', 'icloud'], common: ['apple'],
    legit: ['apple.com', 'icloud.com', 'apple.com.cn', 'icloud.com.cn', 'apple.github.io'] },
  { brand: 'Microsoft', names: ['microsoft', 'outlook', 'hotmail', 'office365'], common: ['outlook'],
    cc: ['microsoft', 'outlook', 'hotmail', 'live'],
    legit: ['microsoft.com', 'microsoftonline.com', 'live.com', 'live.net', 'outlook.com', 'office.com',
      'office365.com', 'msn.com', 'hotmail.com', 'microsoft.github.io'] },
  { brand: 'Facebook', names: ['facebook', 'instagram'],
    legit: ['facebook.com', 'fb.com', 'instagram.com', 'meta.com', 'fbcdn.net', 'cdninstagram.com',
      'facebook.net', 'messenger.com', 'facebook.github.io'] },
  { brand: 'Amazon', names: ['amazon'], common: ['amazon'], cc: ['amazon'],
    legit: ['amazon.com', 'amazonaws.com', 'media-amazon.com', 'ssl-images-amazon.com',
      'amazon-adsystem.com', 'amazontrust.com'] },
  { brand: 'PayPal', names: ['paypal'], legit: ['paypal.com', 'paypal.me', 'paypalobjects.com', 'paypal-community.com'] },
  { brand: 'Netflix', names: ['netflix'], legit: ['netflix.com', 'netflix.net'] },
  { brand: 'Twitter/X', names: ['twitter'], legit: ['twitter.com', 'x.com', 'twimg.com', 't.co'] },
  { brand: 'Telegram', names: ['telegram'], legit: ['telegram.org', 't.me', 'telegram.me'] },
  { brand: 'Sberbank', names: ['sberbank', 'sber'], legit: ['sberbank.ru', 'sber.ru', 'sberbank.com', 'sberbank-ast.ru'] },
  { brand: 'Tinkoff/T-Bank', names: ['tinkoff', 'tbank'], legit: ['tinkoff.ru', 'tbank.ru', 'tinkoff.com'] },
  { brand: 'VTB', names: ['vtb'], legit: ['vtb.ru', 'vtb.com'] },
  { brand: 'Alfa-Bank', names: ['alfabank'], legit: ['alfabank.ru', 'alfa.me', 'alfabank.by', 'alfabank.kz'] },
  { brand: 'WhatsApp', names: ['whatsapp'], legit: ['whatsapp.com', 'whatsapp.net', 'wa.me'] },
  { brand: 'Binance', names: ['binance'], legit: ['binance.com', 'binance.us', 'binance.org'] },
];

function isLegitFor(brand, registrable) {
  if (brand.legit.includes(registrable)) return true;
  return (brand.cc || []).some((l) =>
    new RegExp(`^${l}\\.(?:com|(?:com?|org|net)\\.[a-z]{2}|[a-z]{2})$`).test(registrable));
}

function labelMatchesBrand(label, brand) {
  const flat = label.replace(/-/g, '');
  const tokens = label.split('-');
  const hasPhishToken = tokens.some((t) => PHISH_WORDS.includes(t));
  for (const name of brand.names) {
    const common = (brand.common || []).includes(name);
    // (a) the label is the brand, possibly with lookalike characters (g00gle, paypa1)
    if (squash(flat) === squash(name)) return true;
    // (b) brand as a separate word: paypal-secure, secure-paypal-login
    if (tokens.some((t) => squash(t) === squash(name)) && (!common || hasPhishToken)) return true;
    // (c) brand glued to phishing words: appleidverify, paypallogin2024
    for (const [l, b, words] of [[flat.replace(/\d+$/, ''), name, PHISH_WORDS], [skeleton(flat), skeleton(name), PHISH_WORDS_SKEL]]) {
      if (l.startsWith(b) && isPhishWords(l.slice(b.length), words)) return true;
      if (l.endsWith(b) && isPhishWords(l.slice(0, -b.length), words)) return true;
    }
  }
  return false;
}

/** Brand the hostname imitates, 'Homograph' for mixed-script labels, or null. */
function detectPhishing(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!host.includes('.') || /^[\d.]+$/.test(host)) return null;
  const registrable = getRegistrableDomain(host);
  const rawLabel = registrable.split('.')[0];
  const uniLabel = decodeLabel(rawLabel);
  const isIdn = uniLabel !== rawLabel;
  const latinLabel = isIdn ? [...uniLabel].map((ch) => CONFUSABLES[ch] || ch).join('') : rawLabel;

  for (const brand of BRANDS) {
    if (isLegitFor(brand, registrable)) continue;
    // only an all-Latin result can imitate a Latin brand
    if (!NON_LATIN_LETTER.test(latinLabel) && labelMatchesBrand(latinLabel, brand)) {
      return isIdn ? `${brand.brand} (IDN)` : brand.brand;
    }
    // (d) a brand domain embedded in the subdomain: paypal.com.account-verify.xyz
    for (const d of brand.legit) {
      if (('.' + host).includes('.' + d + '.')) return brand.brand;
    }
  }
  if (isIdn && /[a-z]/.test(uniLabel) && NON_LATIN_LETTER.test(uniLabel)) return 'Homograph';
  return null;
}
// --- end phishing detection ---

function checkPhishing() {
  const brand = detectPhishing(location.hostname);
  if (!brand) return;
  chrome.storage.local.get({ phishingAllowlist: [] }, ({ phishingAllowlist }) => {
    if (Array.isArray(phishingAllowlist) && phishingAllowlist.includes(location.hostname)) return;
    // background shows the warning page; nothing is drawn into the (hostile) page
    chrome.runtime.sendMessage({
      action: 'phishingDetected', brand, domain: location.hostname, url: location.href
    }).catch(() => {});
  });
}

// =============================================
// SETTINGS & INIT
// =============================================
// DEFAULT_SETTINGS comes from defaults.js (same ISOLATED world).

// Runs fn(settings) unless the extension was reloaded; errors stay inside.
function withSettings(fn) {
  try {
    if (!chrome.runtime?.id) return;
    chrome.storage.local.get(DEFAULT_SETTINGS, (settings) => {
      try { fn(settings); } catch {}
    });
  } catch {}
}

function autoScan(firstRun) {
  withSettings((settings) => {
    if (firstRun && settings.antiPhishing !== false) checkPhishing();

    const results = scanStorage();
    if (settings.autoDeleteExpired) {
      const deleted = autoDeleteExpired(results);
      if (deleted.length > 0) {
        const updatedResults = scanStorage();
        chrome.runtime.sendMessage({ action: 'autoScanResult', findings: updatedResults, url: location.href }).catch(() => {});
        return;
      }
    }
    chrome.runtime.sendMessage({ action: 'autoScanResult', findings: results, url: location.href }).catch(() => {});
  });
}

autoScan(true);
setTimeout(autoScan, 2000);

// =============================================
// COOKIE BANNER AUTO-HIDE
// =============================================
// Exact roots of known consent managers. No attribute wildcards: they also
// match page content such as a required #gdpr_consent checkbox.
const COOKIE_SELECTORS = [
  '#cookie-banner', '#cookie-notice', '#cookie-consent', '#cookie-popup', '#cookie-bar',
  '#cookieBanner', '#cookieNotice', '#cookieConsent', '#CookieBanner',
  '.cookie-banner', '.cookie-notice', '.cookie-consent', '.cookie-popup', '.cookie-bar',
  '.cookie-message', '.cookie-overlay', '.cookie-alert',
  '.cookies-banner', '.cookies-notice', '.cookies-popup',
  '.cc-banner', '.cc-window', '.cc-overlay',
  '.gdpr-banner', '.gdpr-popup', '.gdpr-notice', '#gdpr-banner',
  '.consent-banner', '.consent-popup', '#consent-banner',
  '.cmp-banner', '#cmp-container',
  '#onetrust-banner-sdk', '#onetrust-consent-sdk', '.onetrust-pc-dark-filter',
  '.osano-cm-window', '#osano-cm-window',
  '#usercentrics-root', '.uc-banner',
  '#didomi-host', '.didomi-popup-container',
  '.fc-consent-root', '.fc-dialog-container',
  '#qc-cmp2-container', '.qc-cmp2-container',
  '.evidon-banner', '#_evidon_banner',
  '.truste-banner', '#truste-consent-track', '#trustarc-banner-overlay', '#truste-consent-content',
  'iframe[id^="sp_message_iframe"]', 'div[id^="sp_message_container"]',
  'iframe[title*="SP Consent" i]', 'iframe[title*="cookie" i]', 'iframe[title*="consent" i]',
  '[data-testid="cookie-banner"]', '#bbccookies-banner',
];
const COOKIE_CSS = COOKIE_SELECTORS.join(',\n') +
  ' { display: none !important; visibility: hidden !important; pointer-events: none !important; }\n' +
  // SourcePoint locks scrolling with its own class while its (now hidden) message is open
  'html.sp_message_open, body.sp_message_open { overflow: auto !important; }';

let cookieBannerStyleEl = null;
let cookieBannersHidden = 0;

// Consent wording, not just the word "cookie" (recipes have cookies too)
const COOKIE_TEXT_PATTERNS = [
  /we use cookies/i, /(?:site|website|uses|use of|our) cookies/i, /cookies? (?:policy|settings|preferences|consent)/i,
  /использу\S* (?:файлы )?(?:cookie|куки)/i, /файл\S* cookie/i, /cookie-файл/i,
  /nous utilisons des cookies/i, /politique de cookies/i,
  /wir verwenden cookies/i, /cookies verwenden/i,
];
const COOKIE_BUTTON_PATTERNS = [
  /^accept/i, /^agree/i, /^i agree/i, /^got it/i, /^allow (?:all|cookies)/i,
  /^принять/i, /^понятно/i, /^соглас/i, /^разрешить (?:все|cookie)/i,
  /^j'accepte/i, /^tout accepter/i, /^akzeptieren/i, /^alle akzeptieren/i, /^ich stimme zu/i,
];
// Login and sign-up dialogs are never consent banners
const NOT_A_BANNER = /\b(?:sign in|log in|sign up|continue with)\b|войти|вход|регистрац/i;

function isHtmlDocument() {
  return !!document.body && document.documentElement instanceof HTMLElement;
}

function hideCookieBanners(roots) {
  withSettings((settings) => {
    if (!settings.hideCookieBanners || !isHtmlDocument()) return;

    if (!cookieBannerStyleEl) {
      cookieBannerStyleEl = document.createElement('style');
      cookieBannerStyleEl.id = 'tg-cookie-hide';
      cookieBannerStyleEl.textContent = COOKIE_CSS;
      document.documentElement.appendChild(cookieBannerStyleEl);
    }

    let count = 0;
    if (!roots) {
      for (const sel of COOKIE_SELECTORS) {
        try { count += document.querySelectorAll(sel).length; } catch {}
      }
    }
    count += detectAndHideCookieBannersByText(roots || [document.body]);

    if (count > 0 && cookieBannersHidden === 0) {
      cookieBannersHidden = count;
      chrome.runtime.sendMessage({
        action: 'cookieBannerHidden',
        detail: { count, timestamp: Date.now() }
      }).catch(() => {});
    }
  });
}

function isCookieBanner(el) {
  if (el.dataset.tgCookieHidden || el.id === 'tg-cookie-hide') return false;
  // cheap layout checks first: on big pages almost everything fails here
  if (el.offsetHeight === 0 || el.offsetHeight > 400 || el.offsetWidth < 200) return false;
  // banners float over the page: fixed/sticky and stuck to a viewport edge (or a dialog)
  const pos = getComputedStyle(el).position;
  if (pos !== 'fixed' && pos !== 'sticky') return false;
  const rect = el.getBoundingClientRect();
  const atEdge = rect.top <= 24 || rect.bottom >= window.innerHeight - 24;
  const isDialog = el.tagName === 'DIALOG' || /^(?:dialog|alertdialog)$/.test(el.getAttribute('role') || '');
  if (!atEdge && !isDialog) return false;

  const text = el.textContent || '';
  if (text.length < 20 || text.length > 2000) return false;
  if (!COOKIE_TEXT_PATTERNS.some((p) => p.test(text)) || NOT_A_BANNER.test(text)) return false;
  // never touch forms or anything the user can type into
  if (el.closest('form') || el.querySelector('form, input:not([type="button"]):not([type="submit"]), textarea, select')) return false;

  const buttons = el.querySelectorAll('button, a, [role="button"], input[type="button"], input[type="submit"]');
  return [...buttons].some((b) => {
    const label = (b.innerText || b.value || '').trim();
    return COOKIE_BUTTON_PATTERNS.some((p) => p.test(label));
  });
}

function detectAndHideCookieBannersByText(roots) {
  const SELECTOR = 'div, section, aside, footer, dialog, [role="dialog"], [role="banner"], [role="alertdialog"]';
  let hidden = 0;
  for (const root of roots) {
    try {
      const candidates = root.matches?.(SELECTOR) ? [root, ...root.querySelectorAll(SELECTOR)] : root.querySelectorAll(SELECTOR);
      for (const el of candidates) {
        try {
          if (!isCookieBanner(el)) continue;
          el.style.setProperty('display', 'none', 'important');
          el.dataset.tgCookieHidden = '1';
          hidden++;
        } catch { /* ignore per-element errors */ }
      }
    } catch { /* ignore DOM access errors */ }
  }
  // the banner we hid may have locked scrolling with inline styles
  if (hidden > 0) {
    for (const el of [document.documentElement, document.body]) {
      if (el && el.style.overflow === 'hidden') el.style.overflow = '';
    }
  }
  return hidden;
}

// Run cookie hiding with delays to catch dynamically added banners
setTimeout(hideCookieBanners, 500);
setTimeout(hideCookieBanners, 2000);
setTimeout(hideCookieBanners, 5000);

// Watch added nodes only (debounced, auto-disconnect after 30s); our own
// <style> is ignored so hiding banners can't retrigger the observer.
let _cookieDebounce = null;
let _cookieMutationCount = 0;
let _cookiePendingRoots = new Set();
const cookieObserver = new MutationObserver((mutations) => {
  try { if (!chrome.runtime?.id) { cookieObserver.disconnect(); return; } } catch { cookieObserver.disconnect(); return; }
  for (const m of mutations) {
    for (const node of m.addedNodes) {
      if (node.nodeType === 1 && node !== cookieBannerStyleEl) _cookiePendingRoots.add(node);
    }
  }
  if (_cookiePendingRoots.size === 0) return;
  // Auto-disconnect after 200 batches — banner would be found by then
  if (++_cookieMutationCount > 200) { cookieObserver.disconnect(); return; }
  if (_cookieDebounce) clearTimeout(_cookieDebounce);
  _cookieDebounce = setTimeout(() => {
    const roots = [..._cookiePendingRoots].filter((n) => n.isConnected);
    _cookiePendingRoots = new Set();
    if (roots.length) hideCookieBanners(roots);
  }, 500);
});
if (document.documentElement) {
  cookieObserver.observe(document.documentElement, { childList: true, subtree: true });
}
// Also disconnect after 30 seconds regardless — page is loaded by then
setTimeout(() => cookieObserver.disconnect(), 30000);

// =============================================
// JS THREAT SCANNER — analyse external scripts
// =============================================
function jsThreatScan() {
  withSettings((settings) => {
    if (!settings.jsThreatScan) return;

    const scripts = document.querySelectorAll('script[src]');
    const threats = [];
    const currentBase = getRegistrableDomain(location.hostname);

    for (const s of scripts) {
      const src = s.getAttribute('src');
      if (!src) continue;
      let url;
      try { url = new URL(src, location.href); } catch { continue; }

      const isExternal = getRegistrableDomain(url.hostname) !== currentBase;
      if (!isExternal) continue;

      // Check SRI (Subresource Integrity)
      const hasIntegrity = s.hasAttribute('integrity') && s.getAttribute('integrity').length > 10;

      // Suspicious patterns in URL
      const urlLower = url.href.toLowerCase();
      const isSuspiciousDomain = /(\d{1,3}\.){3}\d{1,3}/.test(url.hostname) || // IP address
        url.hostname.length > 40 || // very long hostname
        /[0-9a-f]{16,}/i.test(url.pathname); // hex-heavy path (obfuscation)

      const isSuspiciousPath = /eval|atob|fromcharcode|unescape|document\.write/i.test(url.pathname + url.search);

      if (!hasIntegrity || isSuspiciousDomain || isSuspiciousPath) {
        threats.push({
          src: url.href.substring(0, 200),
          domain: url.hostname,
          noSRI: !hasIntegrity,
          suspiciousDomain: isSuspiciousDomain,
          suspiciousPath: isSuspiciousPath
        });
      }
    }

    // Also check inline scripts for obfuscation patterns
    const inlineScripts = document.querySelectorAll('script:not([src])');
    let obfuscatedCount = 0;
    for (const s of inlineScripts) {
      const code = s.textContent || '';
      if (code.length < 50) continue;
      // Obfuscation signals: very long single line, high density of \x or \u escapes, eval chains
      const hasEvalChain = /eval\s*\(/.test(code) && /atob|fromCharCode|unescape|decodeURI/.test(code);
      const hasHexDensity = (code.match(/\\x[0-9a-f]{2}/gi) || []).length > 20;
      const hasUnicodeDensity = (code.match(/\\u[0-9a-f]{4}/gi) || []).length > 20;
      const singleLongLine = code.indexOf('\n') === -1 && code.length > 2000;
      if (hasEvalChain || hasHexDensity || hasUnicodeDensity || singleLongLine) {
        obfuscatedCount++;
      }
    }

    if (threats.length > 0 || obfuscatedCount > 0) {
      chrome.runtime.sendMessage({
        action: 'jsThreatFound',
        detail: {
          externalThreats: threats.length,
          noSRI: threats.filter(t => t.noSRI).length,
          suspiciousScripts: threats.filter(t => t.suspiciousDomain || t.suspiciousPath).length,
          obfuscatedInline: obfuscatedCount,
          threats: threats.slice(0, 10),
          timestamp: Date.now()
        }
      }).catch(() => {});
    }
  });
}
setTimeout(jsThreatScan, 3000);

// =============================================
// DARK PATTERN DETECTOR — sneaky UI tricks
// =============================================
function detectDarkPatterns() {
  withSettings((settings) => {
    if (!settings.darkPatternDetect) return;

    const patterns = [];

    // 1. Pre-checked checkboxes (newsletter, terms, marketing)
    const checkboxes = document.querySelectorAll('input[type="checkbox"][checked], input[type="checkbox"]:checked');
    for (const cb of checkboxes) {
      const label = cb.closest('label')?.textContent || '';
      const nearby = cb.parentElement?.textContent || '';
      const text = (label + ' ' + nearby).toLowerCase();
      const isSneaky = /subscri|newsletter|marketing|promo|agree|consent|opt.?in|mailing|рассылк|подписк|согласие|рекламн|маркетинг/i.test(text);
      if (isSneaky && cb.checked) {
        patterns.push({ type: 'prechecked', text: text.substring(0, 100).trim() });
      }
    }

    // 2. Hidden costs / forced additions (small text with prices near buttons)
    const buttons = document.querySelectorAll('button, [type="submit"], [role="button"]');
    for (const btn of buttons) {
      const btnText = (btn.textContent || '').toLowerCase();
      if (!/buy|purchase|order|pay|купить|оплатить|заказать|оформить/i.test(btnText)) continue;
      // Check siblings for small-print with prices
      const parent = btn.parentElement;
      if (!parent) continue;
      const smalls = parent.querySelectorAll('small, .small, [class*="fine-print"], [class*="disclaimer"], [style*="font-size"]');
      for (const sm of smalls) {
        const smText = sm.textContent || '';
        if (/recurring|auto.?renew|subscription|trial.*then|после.*пробн|автоматическ.*продлен|подписк.*оформ/i.test(smText)) {
          patterns.push({ type: 'hidden_subscription', text: smText.substring(0, 120).trim() });
        }
      }
    }

    // 3. Fake urgency / countdown timers
    const urgencyEls = document.querySelectorAll('[class*="countdown"], [class*="timer"], [class*="urgency"], [class*="hurry"], [class*="limited"]');
    for (const el of urgencyEls) {
      const text = (el.textContent || '').trim();
      if (text.length > 5 && text.length < 200) {
        if (/\d+\s*:\s*\d+|\d+\s*(min|sec|час|мин|сек|осталось|left|remaining|hurry)/i.test(text)) {
          patterns.push({ type: 'fake_urgency', text: text.substring(0, 100).trim() });
        }
      }
    }

    // 4. Confirmshaming — "No thanks, I don't want to save money"
    const links = document.querySelectorAll('a, button, span');
    for (const el of links) {
      const text = (el.textContent || '').trim();
      if (text.length < 10 || text.length > 150) continue;
      if (/no.*thanks.*i.*(don't|dont|hate|prefer not)|нет.*спасибо.*не.*(хочу|нужн|люблю)/i.test(text)) {
        const style = getComputedStyle(el);
        // Confirmshaming links are usually styled to look less appealing
        if (style.fontSize && parseInt(style.fontSize) <= 13) {
          patterns.push({ type: 'confirmshaming', text: text.substring(0, 100) });
        }
      }
    }

    if (patterns.length > 0) {
      chrome.runtime.sendMessage({
        action: 'darkPatternFound',
        detail: {
          count: patterns.length,
          patterns: patterns.slice(0, 10),
          timestamp: Date.now()
        }
      }).catch(() => {});
    }
  });
}
setTimeout(detectDarkPatterns, 4000);

// =============================================
// BREACH CHECK — check passwords in storage via HIBP Pwned Passwords API
// =============================================
let _breachCheckDone = false;
function breachCheck() {
  if (_breachCheckDone) return;
  withSettings((settings) => {
    if (!settings.breachCheck) return;
    _breachCheckDone = true;

    // Collect password-like values from storage
    const passwordKeys = /(?:password|passwd|secret|pass_|pwd|user_pass)/i;
    const passwords = [];

    function scanStoreForPasswords(storage, storageName) {
      try {
        for (let i = 0; i < storage.length; i++) {
          const key = storage.key(i);
          const v = storage.getItem(key);
          if (!v || v.length < 6 || v.length > 128) continue;
          // Only check keys that look like password fields
          if (passwordKeys.test(key)) {
            passwords.push({ key, value: v, storage: storageName });
          }
        }
      } catch {}
    }
    scanStoreForPasswords(localStorage, 'localStorage');
    scanStoreForPasswords(sessionStorage, 'sessionStorage');

    if (passwords.length === 0) return;

    // Send to background for HIBP check (max 3 to avoid rate limits)
    chrome.runtime.sendMessage({
      action: 'breachCheckRequest',
      passwords: passwords.slice(0, 3).map(p => ({ key: p.key, value: p.value, storage: p.storage }))
    }).catch(() => {});
  });
}
setTimeout(breachCheck, 5000);

// =============================================
// TAB-NAPPING PROTECTION (link hardening)
// =============================================
function hardenLinks() {
  withSettings((settings) => {
    if (!settings.antiTabNapping) return;
    const links = document.querySelectorAll('a[target="_blank"]:not([rel*="noopener"])');
    for (const a of links) {
      const rel = (a.getAttribute('rel') || '').trim();
      a.setAttribute('rel', rel ? rel + ' noopener noreferrer' : 'noopener noreferrer');
    }
  });
}
setTimeout(hardenLinks, 1000);
setTimeout(hardenLinks, 3000);

// =============================================
// javascript: LINKS (report only)
// =============================================
// Links stay untouched: rewriting them broke ASP.NET __doPostBack and hash
// routers. When the setting is on, injected.js cancels the navigation on click.
const TRIVIAL_JS_URL = /^\s*javascript:\s*(?:void\s*\(\s*0\s*\)|void\s+0)?\s*;?\s*$/i;

function reportJavascriptLinks() {
  withSettings((settings) => {
    if (!settings.blockJavascriptUrls) return;
    let count = 0;
    for (const a of document.querySelectorAll('a[href^="javascript:" i]')) {
      if (!TRIVIAL_JS_URL.test(a.getAttribute('href'))) count++;
    }
    if (count > 0) {
      chrome.runtime.sendMessage({
        action: 'jsUrlBlocked',
        detail: { count, timestamp: Date.now() }
      }).catch(() => {});
    }
  });
}
setTimeout(reportJavascriptLinks, 1500);

// =============================================
// BLOCK data: IFRAMES (DOM cleanup)
// =============================================
// data: documents that can run script or render a fake page. blob: URLs are
// same-origin by construction (PDF previews etc.), so they stay; injected.js
// applies the same rule.
function isRiskyDataUrl(src) {
  const m = /^\s*data:([^,;]*)/i.exec(src || '');
  if (!m) return false;
  const mime = m[1].trim().toLowerCase();
  return mime === '' || mime === 'text/html' || mime === 'application/xhtml+xml' || mime === 'image/svg+xml';
}

function blockDataIframes() {
  withSettings((settings) => {
    if (!settings.blockDataIframes) return;
    let blocked = 0;
    for (const iframe of document.querySelectorAll('iframe[src]')) {
      if (isRiskyDataUrl(iframe.getAttribute('src'))) {
        iframe.removeAttribute('src');
        iframe.style.display = 'none';
        blocked++;
      }
    }
    if (blocked > 0) {
      chrome.runtime.sendMessage({
        action: 'dataIframeBlocked',
        detail: { count: blocked, timestamp: Date.now() }
      }).catch(() => {});
    }
  });
}
setTimeout(blockDataIframes, 1000);
setTimeout(blockDataIframes, 3000);

// Events from injected.js are forwarded by settings-preload.js over a private channel.

// =============================================
// AUDIT — passive XSS & SQLi detection
// =============================================
function auditPage() {
  const findings = [];

  // 1. Reflected URL params in DOM (XSS indicator)
  try {
    const params = new URLSearchParams(location.search);
    const bodyHtml = document.body?.innerHTML || '';
    for (const [key, value] of params) {
      if (value.length < 4 || value.length > 500) continue;
      if (bodyHtml.includes(value)) {
        findings.push({
          type: 'xss', subtype: 'reflected_param', severity: 'warning',
          param: key, value: value.substring(0, 80),
          detail: `URL parameter "${key}" is reflected in page HTML`
        });
      }
    }
  } catch {}

  // 2. Dangerous DOM sinks in inline scripts
  try {
    const scripts = document.querySelectorAll('script:not([src])');
    const sinks = [
      { pattern: /\.innerHTML\s*=/, name: 'innerHTML' },
      { pattern: /document\.write\s*\(/, name: 'document.write()' },
      { pattern: /eval\s*\(/, name: 'eval()' },
      { pattern: /setTimeout\s*\(\s*['"`]/, name: 'setTimeout(string)' },
      { pattern: /setInterval\s*\(\s*['"`]/, name: 'setInterval(string)' },
      { pattern: /\.outerHTML\s*=/, name: 'outerHTML' },
      { pattern: /\.insertAdjacentHTML\s*\(/, name: 'insertAdjacentHTML' },
    ];
    let sinkCount = 0;
    for (const script of scripts) {
      const code = script.textContent || '';
      if (code.length < 20) continue;
      for (const sink of sinks) {
        if (sink.pattern.test(code) && sinkCount < 5) {
          sinkCount++;
          findings.push({
            type: 'xss', subtype: 'dom_sink', severity: 'info',
            detail: `Dangerous JS sink: ${sink.name}`
          });
        }
      }
    }
  } catch {}

  // 2b. DOM source→sink: location.hash/search/referrer flowing into innerHTML/eval
  try {
    const scripts = document.querySelectorAll('script:not([src])');
    const sources = [
      { pattern: /location\s*\.\s*hash/, name: 'location.hash' },
      { pattern: /location\s*\.\s*search/, name: 'location.search' },
      { pattern: /location\s*\.\s*href/, name: 'location.href' },
      { pattern: /document\s*\.\s*referrer/, name: 'document.referrer' },
      { pattern: /document\s*\.\s*URL\b/, name: 'document.URL' },
      { pattern: /window\s*\.\s*name\b/, name: 'window.name' },
    ];
    const dangerousSinks = /innerHTML|outerHTML|document\.write|eval\s*\(|insertAdjacentHTML|setTimeout|setInterval/;
    for (const script of scripts) {
      const code = script.textContent || '';
      if (code.length < 30) continue;
      for (const src of sources) {
        if (src.pattern.test(code) && dangerousSinks.test(code)) {
          findings.push({
            type: 'xss', subtype: 'dom_source_sink', severity: 'warning',
            detail: `DOM XSS risk: ${src.name} used alongside dangerous sink`
          });
          break;
        }
      }
    }
  } catch {}

  // 2c. javascript: URLs in links
  try {
    const jsLinks = document.querySelectorAll('a[href^="javascript:" i]');
    if (jsLinks.length > 0) {
      findings.push({
        type: 'xss', subtype: 'javascript_uri', severity: 'warning',
        detail: `${jsLinks.length} link(s) with javascript: URL`,
        count: jsLinks.length
      });
    }
  } catch {}

  // 2d. Inline event handlers with dynamic data
  try {
    const dangerousHandlers = document.querySelectorAll(
      '[onload], [onerror], [onclick], [onmouseover], [onfocus], [onblur], [onsubmit], [onchange], [onkeyup], [onkeydown]'
    );
    let inlineCount = 0;
    for (const el of dangerousHandlers) {
      const attrs = el.attributes;
      for (const attr of attrs) {
        if (/^on/i.test(attr.name) && attr.value.length > 10) {
          inlineCount++;
        }
      }
    }
    if (inlineCount > 0) {
      findings.push({
        type: 'xss', subtype: 'inline_handlers', severity: 'info',
        detail: `${inlineCount} inline event handler(s) (onclick, onerror, etc.)`,
        count: inlineCount
      });
    }
  } catch {}

  // 2e. data: URIs in iframes/objects (XSS vector)
  try {
    const dataFrames = document.querySelectorAll(
      'iframe[src^="data:"], object[data^="data:"], embed[src^="data:"]'
    );
    if (dataFrames.length > 0) {
      findings.push({
        type: 'xss', subtype: 'data_uri', severity: 'warning',
        detail: `${dataFrames.length} iframe/object with data: URI — possible XSS vector`,
        count: dataFrames.length
      });
    }
  } catch {}

  // 3. SQL/NoSQL error messages on page
  try {
    const bodyText = document.body?.innerText || '';
    const sqlErrors = [
      // MySQL / MariaDB
      { pattern: /SQL syntax.*MySQL/i, db: 'MySQL' },
      { pattern: /Warning.*mysql_/i, db: 'MySQL' },
      { pattern: /MySqlException/i, db: 'MySQL' },
      { pattern: /valid MySQL result/i, db: 'MySQL' },
      { pattern: /MariaDB server version/i, db: 'MariaDB' },
      // PostgreSQL
      { pattern: /PostgreSQL.*ERROR/i, db: 'PostgreSQL' },
      { pattern: /pg_query\(\)/i, db: 'PostgreSQL' },
      { pattern: /PSQLException/i, db: 'PostgreSQL' },
      { pattern: /ERROR:\s+syntax error at or near/i, db: 'PostgreSQL' },
      // MSSQL
      { pattern: /Microsoft.*ODBC.*SQL/i, db: 'MSSQL' },
      { pattern: /Unclosed quotation mark/i, db: 'MSSQL' },
      { pattern: /SqlException/i, db: 'MSSQL' },
      { pattern: /Microsoft SQL Native Client/i, db: 'MSSQL' },
      // Oracle
      { pattern: /ORA-\d{5}/i, db: 'Oracle' },
      { pattern: /Oracle.*Driver/i, db: 'Oracle' },
      // SQLite
      { pattern: /SQLite3?::Exception/i, db: 'SQLite' },
      { pattern: /SQLITE_ERROR/i, db: 'SQLite' },
      { pattern: /near ".*": syntax error/i, db: 'SQLite' },
      // PHP
      { pattern: /PDOException/i, db: 'PHP PDO' },
      { pattern: /SQLSTATE\[/i, db: 'SQL' },
      // Java
      { pattern: /java\.sql\.SQLException/i, db: 'Java JDBC' },
      { pattern: /org\.hibernate/i, db: 'Java Hibernate' },
      // Python
      { pattern: /psycopg2\..*Error/i, db: 'Python psycopg2' },
      { pattern: /pymysql\..*Error/i, db: 'Python pymysql' },
      { pattern: /sqlite3\.OperationalError/i, db: 'Python SQLite' },
      { pattern: /django\.db\.utils/i, db: 'Django' },
      { pattern: /sqlalchemy\.exc\./i, db: 'SQLAlchemy' },
      // .NET
      { pattern: /System\.Data\.SqlClient/i, db: '.NET MSSQL' },
      { pattern: /Npgsql\..*Exception/i, db: '.NET PostgreSQL' },
      // Ruby
      { pattern: /ActiveRecord::StatementInvalid/i, db: 'Ruby on Rails' },
      { pattern: /PG::SyntaxError/i, db: 'Ruby PG' },
      // NoSQL (MongoDB)
      { pattern: /MongoError/i, db: 'MongoDB' },
      { pattern: /MongoServerError/i, db: 'MongoDB' },
      // Generic
      { pattern: /SQL error/i, db: 'SQL' },
      { pattern: /database error/i, db: 'Database' },
      { pattern: /syntax error.*SQL/i, db: 'SQL' },
    ];
    for (const err of sqlErrors) {
      if (err.pattern.test(bodyText)) {
        findings.push({
          type: 'sqli', subtype: 'error_message', severity: 'critical',
          db: err.db, detail: `SQL error visible on page (${err.db})`
        });
        break;
      }
    }
  } catch {}

  // 4. CSRF — forms without token
  try {
    const forms = document.querySelectorAll('form[method="post" i]');
    for (const form of forms) {
      const hasCSRF = form.querySelector(
        'input[name*="csrf" i], input[name*="_token" i], input[name*="nonce" i], ' +
        'input[name*="authenticity" i], input[name*="xsrf" i], input[name*="__RequestVerificationToken" i]'
      );
      if (!hasCSRF) {
        findings.push({
          type: 'csrf', subtype: 'no_csrf_token', severity: 'warning',
          detail: 'POST form without CSRF token',
          url: (form.getAttribute('action') || '').substring(0, 100)
        });
      }
    }
  } catch {}

  // 5. CSRF — meta tag check
  try {
    const csrfMeta = document.querySelector(
      'meta[name*="csrf" i], meta[name*="xsrf" i], meta[name*="_token" i]'
    );
    if (!csrfMeta) {
      const hasForms = document.querySelectorAll('form[method="post" i]').length > 0;
      if (hasForms) {
        findings.push({
          type: 'csrf', subtype: 'no_csrf_meta', severity: 'info',
          detail: 'No CSRF meta tag found (some frameworks use <meta name="csrf-token">)'
        });
      }
    }
  } catch {}

  // 6. CSRF — cookies without SameSite
  try {
    const cookies = document.cookie.split(';');
    let sessionCookieCount = 0;
    for (const cookie of cookies) {
      const eqIdx = cookie.indexOf('=');
      if (eqIdx === -1) continue;
      const key = cookie.substring(0, eqIdx).trim().toLowerCase();
      if (/session|sid|auth|login|token|jwt/i.test(key)) {
        sessionCookieCount++;
      }
    }
    // We can't read SameSite from JS, but we can check via the background script later.
    // For now, just flag session cookies exist (background will enrich with header info)
    if (sessionCookieCount > 0) {
      findings.push({
        type: 'csrf', subtype: 'session_cookies', severity: 'info',
        detail: `${sessionCookieCount} session cookie(s) found — check SameSite attribute in Headers tab`,
        count: sessionCookieCount
      });
    }
  } catch {}

  // 7. IDOR — numeric IDs in URL path
  try {
    const path = location.pathname;
    const idPatterns = [
      { pattern: /\/(?:user|users|profile|account|admin)\/(\d+)/i, name: 'User ID' },
      { pattern: /\/(?:order|orders|invoice|invoices)\/(\d+)/i, name: 'Order ID' },
      { pattern: /\/(?:post|posts|article|articles|page|pages)\/(\d+)/i, name: 'Post ID' },
      { pattern: /\/(?:message|messages|chat|conversation)\/(\d+)/i, name: 'Message ID' },
      { pattern: /\/(?:file|files|document|documents|doc)\/(\d+)/i, name: 'File ID' },
      { pattern: /\/(?:comment|comments|review|reviews)\/(\d+)/i, name: 'Comment ID' },
      { pattern: /\/(?:api|v\d+)\/\w+\/(\d+)/i, name: 'API Resource ID' },
    ];
    for (const idp of idPatterns) {
      const match = path.match(idp.pattern);
      if (match) {
        findings.push({
          type: 'idor', subtype: 'path_id', severity: 'info',
          detail: `${idp.name} in URL path: ${match[1]}`,
          id: match[1]
        });
      }
    }
  } catch {}

  // 8. IDOR — numeric IDs in URL params
  try {
    const params = new URLSearchParams(location.search);
    const idParamNames = /^(id|user_?id|uid|account_?id|order_?id|item_?id|doc_?id|file_?id|msg_?id|profile_?id|pid|oid)$/i;
    for (const [key, value] of params) {
      if (idParamNames.test(key) && /^\d+$/.test(value)) {
        findings.push({
          type: 'idor', subtype: 'param_id', severity: 'info',
          detail: `Numeric ID in parameter "${key}" = ${value}`,
          param: key, id: value
        });
      }
    }
  } catch {}

  // 9. IDOR — API calls with numeric IDs in inline scripts
  try {
    const scripts = document.querySelectorAll('script:not([src])');
    const apiPattern = /(?:fetch|axios|ajax|\$\.(?:get|post))\s*\(\s*['"`]([^'"`]*\/\d+[^'"`]*)[`'"]/g;
    let idorApiCount = 0;
    for (const script of scripts) {
      const code = script.textContent || '';
      if (code.length < 30) continue;
      let m;
      while ((m = apiPattern.exec(code)) !== null && idorApiCount < 3) {
        idorApiCount++;
        findings.push({
          type: 'idor', subtype: 'api_call', severity: 'info',
          detail: `API call with numeric ID: ${m[1].substring(0, 80)}`
        });
      }
    }
  } catch {}

  // 10. Open Redirect — URL params pointing to external domains
  try {
    const params = new URLSearchParams(location.search);
    const redirectKeys = /^(redirect|redirect_uri|redirect_url|return|return_to|returnurl|next|url|goto|target|dest|destination|continue|rurl|out|link|to)$/i;
    for (const [key, value] of params) {
      if (!redirectKeys.test(key)) continue;
      // Check if value is an external URL
      try {
        const target = new URL(value, location.href);
        const currentBase = getRegistrableDomain(location.hostname);
        const targetBase = getRegistrableDomain(target.hostname);
        if (target.hostname && targetBase !== currentBase) {
          findings.push({
            type: 'redirect', subtype: 'open_redirect', severity: 'warning',
            detail: `Open Redirect: "${key}" points to external domain`,
            param: key, url: value.substring(0, 100)
          });
        }
      } catch {}
    }
  } catch {}

  // 11. Mixed Content — HTTP resources on HTTPS page
  try {
    if (location.protocol === 'https:') {
      const httpResources = [];
      // Scripts
      for (const el of document.querySelectorAll('script[src^="http:"]')) {
        httpResources.push({ tag: 'script', src: el.getAttribute('src').substring(0, 80) });
      }
      // Stylesheets
      for (const el of document.querySelectorAll('link[rel="stylesheet"][href^="http:"]')) {
        httpResources.push({ tag: 'link', src: el.getAttribute('href').substring(0, 80) });
      }
      // Iframes
      for (const el of document.querySelectorAll('iframe[src^="http:"]')) {
        httpResources.push({ tag: 'iframe', src: el.getAttribute('src').substring(0, 80) });
      }
      if (httpResources.length > 0) {
        findings.push({
          type: 'mixed', subtype: 'mixed_content', severity: 'warning',
          detail: `${httpResources.length} HTTP resource(s) on HTTPS page (${httpResources.slice(0, 2).map(r => r.tag).join(', ')})`,
          count: httpResources.length
        });
      }
    }
  } catch {}

  // 12. Information Disclosure — sensitive HTML comments
  try {
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    const sensitivePatterns = [
      /password/i, /passwd/i, /secret/i, /api[_-]?key/i, /token/i,
      /TODO/i, /FIXME/i, /HACK/i, /BUG/i, /DEBUG/i,
      /\/etc\/passwd/i, /\.env/i, /config\./i,
      /admin/i, /root/i, /database/i, /mysql/i, /postgres/i,
      /BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE/i,
    ];
    let sensitiveComments = 0;
    let commentExamples = [];
    while (walker.nextNode()) {
      const text = walker.currentNode.textContent.trim();
      if (text.length < 5 || text.length > 2000) continue;
      for (const pat of sensitivePatterns) {
        if (pat.test(text)) {
          sensitiveComments++;
          if (commentExamples.length < 2) {
            commentExamples.push(text.substring(0, 60));
          }
          break;
        }
      }
    }
    if (sensitiveComments > 0) {
      findings.push({
        type: 'info_disclosure', subtype: 'html_comments', severity: 'info',
        detail: `${sensitiveComments} HTML comment(s) with sensitive keywords`,
        examples: commentExamples
      });
    }
  } catch {}

  // 13. Collect URL params for active testing
  const urlParams = [];
  try {
    const params = new URLSearchParams(location.search);
    for (const [key, value] of params) {
      urlParams.push({ key, value });
    }
  } catch {}

  // 14. Collect forms for active testing
  const pageForms = [];
  try {
    const forms = document.querySelectorAll('form');
    for (const form of forms) {
      const action = form.getAttribute('action') || '';
      const method = (form.getAttribute('method') || 'GET').toUpperCase();
      const inputs = [];
      for (const input of form.querySelectorAll('input[name], textarea[name], select[name]')) {
        const type = (input.getAttribute('type') || 'text').toLowerCase();
        // Never collect passwords; values stay on the page (the audit sends placeholders)
        if (['submit', 'button', 'hidden', 'file', 'image', 'password'].includes(type)) continue;
        inputs.push({ name: input.getAttribute('name'), type });
      }
      if (inputs.length > 0) {
        // Resolve absolute action URL
        let actionUrl = action;
        try { actionUrl = new URL(action, location.href).href; } catch {}
        pageForms.push({ action: actionUrl, method, inputs });
      }
    }
  } catch {}

  return { findings, urlParams, pageForms, url: location.href };
}

// Expire a cookie on every path/domain combination it could have been set
// with; document.cookie can't tell us which one it was.
function deleteCookie(name) {
  const segments = location.pathname.split('/').filter(Boolean);
  const paths = new Set(['/']);
  for (let i = 1; i <= segments.length; i++) {
    const p = '/' + segments.slice(0, i).join('/');
    paths.add(p);
    paths.add(p + '/');
  }
  const domains = [''];
  const registrable = getRegistrableDomain(location.hostname);
  for (let host = location.hostname; host; host = host.slice(host.indexOf('.') + 1)) {
    domains.push('; domain=' + host);
    if (host === registrable || !host.includes('.')) break;
  }
  const secure = location.protocol === 'https:' ? '; secure' : '';
  for (const path of paths) {
    for (const domain of domains) {
      document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; max-age=0; path=${path}${domain}${secure}`;
    }
  }
  return !document.cookie.split(';').some((c) => c.split('=')[0].trim() === name);
}

// Слушаем запросы (all answers are synchronous)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scan') {
    sendResponse({ findings: scanStorage(), url: location.href });
  } else if (request.action === 'removeItem') {
    try {
      if (request.storage === 'cookie') {
        sendResponse(deleteCookie(request.key)
          ? { success: true }
          : { success: false, error: 'httpOnly or inaccessible' });
      } else {
        const store = request.storage === 'sessionStorage' ? sessionStorage : localStorage;
        store.removeItem(request.key);
        sendResponse({ success: true });
      }
    } catch (e) { sendResponse({ success: false, error: e.message }); }
  } else if (request.action === 'detectTLS') {
    // Pages can't see TLS parameters; only the negotiated HTTP protocol is known
    let protocol = null;
    try { protocol = performance.getEntriesByType('navigation')[0]?.nextHopProtocol || null; } catch {}
    sendResponse({ protocol });
  } else if (request.action === 'auditPage') {
    sendResponse(auditPage());
  } else if (request.action === 'settingsUpdated') {
    // injected.js picks changes up via chrome.storage.onChanged in settings-preload.js
    sendResponse({ ok: true });
  }
});
