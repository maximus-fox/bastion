/**
 * Bastion — Content Script (ISOLATED world)
 * Scanner, anti-phishing overlay, bridge for injected.js
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
    if (f.type === 'jwt' && f.expired === true) {
      try {
        const store = f.storage === 'sessionStorage' ? sessionStorage : localStorage;
        store.removeItem(f.key);
        deleted.push({ key: f.key, storage: f.storage });
      } catch {}
    }
  }
  if (deleted.length > 0) {
    chrome.runtime.sendMessage({ action: 'autoDeletedExpired', deleted, url: location.href }).catch(() => {});
  }
  return deleted;
}

// =============================================
// ANTI-PHISHING — проверка домена
// =============================================
const BRAND_PATTERNS = [
  { brand: 'Google', legit: ['google.com','google.ru','google.dev','google.ai','google.co','gmail.com','youtube.com','googleapis.com','withgoogle.com','gstatic.com','googlevideo.com'], pattern: /go+g[li1|]+e|gma[li1]+l|youtu[b8]e/i },
  { brand: 'Apple', legit: ['apple.com','icloud.com'], pattern: /app[li1]+e|[li1]c[li1]oud/i },
  { brand: 'Microsoft', legit: ['microsoft.com','outlook.com','live.com','office.com','office365.com'], pattern: /m[li1]crosoft|out[li1]ook|hotma[li1]+l/i },
  { brand: 'Facebook', legit: ['facebook.com','fb.com','instagram.com','meta.com'], pattern: /faceb[o0]+k|[li1]nstagram/i },
  { brand: 'Amazon', legit: ['amazon.com','amazon.ru','aws.amazon.com'], pattern: /amaz[o0]n|4maz[o0]n/i },
  { brand: 'PayPal', legit: ['paypal.com'], pattern: /paypa[li1]+|payp[a4][li1]/i },
  { brand: 'Netflix', legit: ['netflix.com'], pattern: /netf[li1]+[xk]|n[e3]tf[li1]ix/i },
  { brand: 'Twitter/X', legit: ['twitter.com','x.com'], pattern: /tw[li1]+tter/i },
  { brand: 'Telegram', legit: ['telegram.org','t.me','web.telegram.org'], pattern: /te[li1]+egram|t[e3][li1]egr[a4]m/i },
  { brand: 'Sberbank', legit: ['sberbank.ru','online.sberbank.ru','sber.ru'], pattern: /s[b8]er[b8]ank|c[b8]ep[b8]ahk/i },
  { brand: 'Tinkoff/T-Bank', legit: ['tinkoff.ru','tbank.ru','tinkoff.com'], pattern: /t[li1]nk[o0]ff|t[b8]ank/i },
  { brand: 'VTB', legit: ['vtb.ru','online.vtb.ru'], pattern: /v[t7][b8]/i },
  { brand: 'Alfa-Bank', legit: ['alfabank.ru','alfa.me'], pattern: /a[li1]fa[b8]ank|a[li1]+pha[b8]ank/i },
  { brand: 'WhatsApp', legit: ['whatsapp.com','web.whatsapp.com'], pattern: /wh[a4]ts[a4]pp|wh[a4]ts[a4]+p/i },
  { brand: 'Binance', legit: ['binance.com','binance.us'], pattern: /b[li1]n[a4]nce|b[li1]+nance/i },
];

function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  const doubleTlds = ['co.uk','com.br','co.jp','com.au','co.in','co.kr','co.nz','com.cn','com.mx','com.tr','org.uk','net.uk'];
  const last2 = parts.slice(-2).join('.');
  if (doubleTlds.includes(last2) && parts.length >= 3) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

function checkPhishing() {
  const hostname = location.hostname;
  const baseDomain = getBaseDomain(hostname);

  for (const brand of BRAND_PATTERNS) {
    // Если это легитимный домен — пропускаем
    if (brand.legit.some(d => baseDomain === d || hostname.endsWith('.' + d))) continue;

    // Проверяем паттерн
    if (brand.pattern.test(baseDomain) || brand.pattern.test(hostname)) {
      showPhishingWarning(brand.brand, hostname);
      chrome.runtime.sendMessage({
        action: 'phishingDetected',
        brand: brand.brand,
        domain: hostname,
        url: location.href
      }).catch(() => {});
      return;
    }
  }

  // Проверка гомографических атак (кириллица в латинских доменах)
  const hasCyrillic = /[\u0400-\u04FF]/.test(hostname);
  const hasLatin = /[a-zA-Z]/.test(hostname);
  if (hasCyrillic && hasLatin) {
    showPhishingWarning('Mixed Script (Homograph)', hostname);
    chrome.runtime.sendMessage({
      action: 'phishingDetected',
      brand: 'Homograph Attack',
      domain: hostname,
      url: location.href
    }).catch(() => {});
    return;
  }

  // Punycode (xn--) domains — browser may display IDN as unicode, check raw hostname
  if (hostname.includes('xn--')) {
    // Decode punycode and re-check against brand patterns
    try {
      const decoded = new URL(location.href).hostname; // browser already decodes
      for (const brand of BRAND_PATTERNS) {
        if (brand.legit.some(d => baseDomain === d || hostname.endsWith('.' + d))) continue;
        if (brand.pattern.test(decoded) || brand.pattern.test(baseDomain)) {
          showPhishingWarning(brand.brand + ' (Punycode)', hostname);
          chrome.runtime.sendMessage({
            action: 'phishingDetected',
            brand: brand.brand + ' (IDN/Punycode)',
            domain: hostname,
            url: location.href
          }).catch(() => {});
          return;
        }
      }
    } catch {}
  }
}

function showPhishingWarning(brand, domain) {
  const overlay = document.createElement('div');
  overlay.id = 'tg-phishing-overlay';
  overlay.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(200,0,0,0.95);z-index:2147483647;
      display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:-apple-system,sans-serif;color:#fff;padding:40px;text-align:center;">
      <div style="font-size:72px;margin-bottom:20px;">&#9888;&#65039;</div>
      <div style="font-size:28px;font-weight:700;margin-bottom:12px;">Bastion: Phishing Detected!</div>
      <div style="font-size:18px;margin-bottom:8px;opacity:0.9;">This site <b>${domain}</b></div>
      <div style="font-size:18px;margin-bottom:24px;opacity:0.9;">is pretending to be <b>${brand}</b></div>
      <div style="font-size:14px;max-width:500px;line-height:1.5;opacity:0.8;margin-bottom:30px;">
        The domain name looks like a well-known brand but it's fake. This is likely a phishing site designed to steal your credentials. Do NOT enter any passwords or personal data.
      </div>
      <div style="display:flex;gap:12px;">
        <button id="tg-phish-back" style="padding:12px 32px;font-size:16px;font-weight:600;background:#fff;color:#c00;border:none;border-radius:8px;cursor:pointer;">
          &#8592; Go Back (Safe)
        </button>
        <button id="tg-phish-dismiss" style="padding:12px 32px;font-size:14px;background:transparent;color:#fff;border:1px solid rgba(255,255,255,0.4);border-radius:8px;cursor:pointer;">
          I understand the risk, continue
        </button>
      </div>
    </div>`;
  document.documentElement.appendChild(overlay);

  overlay.addEventListener('click', (e) => {
    if (e.target.id === 'tg-phish-back' || e.target.closest('#tg-phish-back')) {
      if (history.length > 1) history.back(); else window.close();
    }
    if (e.target.id === 'tg-phish-dismiss' || e.target.closest('#tg-phish-dismiss')) {
      overlay.remove();
    }
  }, { capture: true });
}

// =============================================
// SETTINGS & INIT
// =============================================
// DEFAULT_SETTINGS comes from defaults.js (same ISOLATED world).

function autoScan() {
  try {
  if (!chrome.runtime?.id) return;
  chrome.storage.local.get(DEFAULT_SETTINGS, (settings) => {
    // Антифишинг
    if (settings.antiPhishing !== false) {
      checkPhishing();
    }

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
  } catch {}
}

autoScan();
setTimeout(autoScan, 2000);

// =============================================
// COOKIE BANNER AUTO-HIDE
// =============================================
const COOKIE_SELECTORS = [
  '#cookie-banner', '#cookie-notice', '#cookie-consent', '#cookie-popup', '#cookie-bar',
  '#cookieBanner', '#cookieNotice', '#cookieConsent', '#CookieBanner',
  '.cookie-banner', '.cookie-notice', '.cookie-consent', '.cookie-popup', '.cookie-bar',
  '.cookie-message', '.cookie-overlay', '.cookie-wrapper', '.cookie-alert',
  '.cookies-banner', '.cookies-notice', '.cookies-popup',
  '.cc-banner', '.cc-window', '.cc-overlay',
  '[class*="cookie-banner"]', '[class*="cookie-consent"]', '[class*="cookie-notice"]',
  '[class*="cookieBanner"]', '[class*="cookieConsent"]', '[class*="cookieNotice"]',
  '[id*="cookie-banner"]', '[id*="cookie-consent"]', '[id*="cookie-notice"]',
  '[id*="gdpr"]', '.gdpr-banner', '.gdpr-popup', '.gdpr-notice', '#gdpr-banner',
  '[class*="gdpr-banner"]', '[class*="gdpr-consent"]',
  '[class*="consent-banner"]', '[class*="consent-popup"]', '[class*="consent-notice"]',
  '.consent-banner', '.consent-popup', '#consent-banner',
  '[aria-label*="cookie" i]', '[aria-label*="consent" i]',
  '.cmp-container', '#cmp-container', '.cmp-banner',
  '#onetrust-banner-sdk', '#onetrust-consent-sdk', '.onetrust-pc-dark-filter',
  '.osano-cm-window', '#osano-cm-window',
  '#usercentrics-root', '.uc-banner',
  '#didomi-host', '.didomi-popup-container',
  '.fc-consent-root', '.fc-dialog-container',
  '#qc-cmp2-container', '.qc-cmp2-container',
  '.evidon-banner', '#_evidon_banner',
  '.truste-banner', '#truste-consent-track',
  '#sp_message_container_', '.message-container[class*="sp_"]',
  '[data-testid="cookie-banner"]', '#bbccookies-banner',
  '[class*="cookie-banner-"]', '[id*="cookie-banner-"]',
];

let cookieBannerStyleEl = null;
let cookieBannersHidden = 0;

// Text patterns for cookie banner detection (multi-language)
const COOKIE_TEXT_PATTERNS = [
  /cookie/i, /куки/i, /cookie-файл/i,
  /we use cookies/i, /this site uses cookies/i, /uses cookies/i,
  /использует cookie/i, /использует куки/i, /файлы cookie/i,
  /politique de cookies/i, /nous utilisons des cookies/i,
  /wir verwenden cookies/i, /cookies verwenden/i,
];
const COOKIE_BUTTON_PATTERNS = [
  /^accept/i, /^принять/i, /^agree/i, /^ok$/i, /^got it/i, /^i agree/i,
  /^понятно/i, /^согласен/i, /^соглас/i, /^allow/i, /^разрешить/i,
  /^accept all/i, /^принять все/i, /^j'accepte/i, /^akzeptieren/i,
  /^yes/i, /^да[,.]?\s/i, /^allow all/i, /^разрешить все/i,
  /^continue/i, /^продолжить/i, /^ich stimme zu/i,
];

function hideCookieBanners() {
  try {
  if (!chrome.runtime?.id) { cookieObserver.disconnect(); return; }
  chrome.storage.local.get(DEFAULT_SETTINGS, (settings) => {
    if (!settings.hideCookieBanners) return;

    // Inject CSS to hide known selectors
    if (!cookieBannerStyleEl) {
      cookieBannerStyleEl = document.createElement('style');
      cookieBannerStyleEl.id = 'tg-cookie-hide';
      document.documentElement.appendChild(cookieBannerStyleEl);
    }
    cookieBannerStyleEl.textContent = COOKIE_SELECTORS.map(
      s => `${s} { display: none !important; visibility: hidden !important; opacity: 0 !important; pointer-events: none !important; }`
    ).join('\n');

    // Also hide overlay/backdrop that blocks the page
    // Including iframe-based consent managers (SourcePoint, OneTrust, TrustArc, etc.)
    const overlayCSS = `
      body.cookie-overlay, body.no-scroll, body.modal-open { overflow: auto !important; }
      .cookie-overlay-bg, .cc-overlay, .cmp-overlay, .consent-overlay,
      [class*="cookie-overlay"], [class*="consent-overlay"],
      .onetrust-pc-dark-filter { display: none !important; }
      iframe[id^="sp_message_iframe"] { display: none !important; }
      div[id^="sp_message_container"] { display: none !important; }
      .sp_message_open { overflow: auto !important; }
      div.fc-consent-root iframe { display: none !important; }
      #trustarc-banner-overlay, #truste-consent-content { display: none !important; }
      iframe[id*="consent"], iframe[title*="cookie" i], iframe[title*="consent" i],
      iframe[title*="Privacy" i], iframe[title*="SP Consent" i] { display: none !important; }
    `;
    cookieBannerStyleEl.textContent += overlayCSS;

    // Hide iframe-based consent managers via JS (SourcePoint, etc.)
    const iframeSelectors = [
      'iframe[id^="sp_message_iframe"]',
      'div[id^="sp_message_container"]',
      'iframe[title*="SP Consent" i]',
      'iframe[title*="cookie" i]',
      'iframe[title*="consent" i]',
      'iframe[title*="Privacy Manager" i]',
    ];
    for (const sel of iframeSelectors) {
      try {
        for (const el of document.querySelectorAll(sel)) {
          el.style.setProperty('display', 'none', 'important');
          // Also hide parent container if it's a wrapper div
          const parent = el.parentElement;
          if (parent && parent.children.length <= 2 && parent.id && /sp_message|consent|cookie/i.test(parent.id)) {
            parent.style.setProperty('display', 'none', 'important');
          }
        }
      } catch {}
    }
    // Restore body scroll if locked by consent manager
    if (document.body.classList.contains('sp_message_open')) {
      document.body.classList.remove('sp_message_open');
      document.body.style.overflow = '';
    }

    // Count CSS-hidden elements
    let count = 0;
    for (const sel of COOKIE_SELECTORS) {
      try {
        const els = document.querySelectorAll(sel);
        for (const el of els) {
          if (el.offsetHeight > 0 || el.style.display !== 'none') count++;
        }
      } catch {}
    }

    // Smart text-based detection for custom cookie banners
    count += detectAndHideCookieBannersByText();

    if (count > 0 && cookieBannersHidden === 0) {
      cookieBannersHidden = count;
      chrome.runtime.sendMessage({
        action: 'cookieBannerHidden',
        detail: { count, timestamp: Date.now() }
      }).catch(() => {});
    }
  });
  } catch { cookieObserver.disconnect(); }
}

function detectAndHideCookieBannersByText() {
  let hidden = 0;
  try {
    // Look for fixed/sticky positioned elements at top or bottom of page
    const candidates = document.querySelectorAll('div, section, aside, footer, [role="dialog"], [role="banner"], [role="alertdialog"]');
    for (const el of candidates) {
      try {
        // Skip already hidden or tiny elements
        if (el.id === 'tg-cookie-hide' || el.id === 'tg-phishing-overlay') continue;
        if (el.dataset.tgCookieHidden) continue;
        if (el.offsetHeight === 0 || el.offsetHeight > 400) continue; // banners are typically < 400px tall
        if (el.offsetWidth < 200) continue;

        const style = getComputedStyle(el);
        const pos = style.position;
        // Cookie banners are usually fixed or sticky, sometimes absolute
        const isPositioned = pos === 'fixed' || pos === 'sticky' ||
          (pos === 'absolute' && (parseInt(style.bottom) <= 20 || parseInt(style.top) <= 20));
        // Also check if element is near the very bottom or top of viewport
        const rect = el.getBoundingClientRect();
        const isEdge = rect.bottom > window.innerHeight - 150 || rect.top < 150;

        if (!isPositioned && !isEdge) continue;

        // Check if text content mentions cookies
        const text = el.innerText || '';
        if (text.length < 20 || text.length > 2000) continue; // too short or too long
        const hasCookieText = COOKIE_TEXT_PATTERNS.some(p => p.test(text));
        if (!hasCookieText) continue;

        // Check if it has a button that looks like "Accept" / "Принять"
        const buttons = el.querySelectorAll('button, a[role="button"], input[type="button"], input[type="submit"], [class*="btn"], [class*="button"]');
        let hasAcceptButton = false;
        for (const btn of buttons) {
          const btnText = (btn.innerText || btn.value || '').trim();
          if (COOKIE_BUTTON_PATTERNS.some(p => p.test(btnText))) {
            hasAcceptButton = true;
            break;
          }
        }

        // If it has cookie text + accept button → it's a cookie banner, hide it
        if (hasAcceptButton) {
          el.style.setProperty('display', 'none', 'important');
          el.style.setProperty('visibility', 'hidden', 'important');
          el.style.setProperty('opacity', '0', 'important');
          el.dataset.tgCookieHidden = '1';
          hidden++;
          // Also restore body scroll if banner was blocking it
          if (document.body.style.overflow === 'hidden') {
            document.body.style.overflow = '';
          }
        }
      } catch (_) { /* ignore per-element errors from page CSP/CORS */ }
    }
  } catch (_) { /* ignore DOM access errors */ }
  return hidden;
}

// Run cookie hiding with delays to catch dynamically added banners
setTimeout(hideCookieBanners, 500);
setTimeout(hideCookieBanners, 2000);
setTimeout(hideCookieBanners, 5000);

// Watch for dynamically added cookie banners (debounced, auto-disconnect after 30s)
let _cookieDebounce = null;
let _cookieMutationCount = 0;
const cookieObserver = new MutationObserver(() => {
  try { if (!chrome.runtime?.id) { cookieObserver.disconnect(); return; } } catch { cookieObserver.disconnect(); return; }
  _cookieMutationCount++;
  // Auto-disconnect after 200 mutations — banner would be found by then
  if (_cookieMutationCount > 200) { cookieObserver.disconnect(); return; }
  if (_cookieDebounce) clearTimeout(_cookieDebounce);
  _cookieDebounce = setTimeout(hideCookieBanners, 500);
});
cookieObserver.observe(document.documentElement, { childList: true, subtree: true });
// Also disconnect after 30 seconds regardless — page is loaded by then
setTimeout(() => cookieObserver.disconnect(), 30000);

// =============================================
// JS THREAT SCANNER — analyse external scripts
// =============================================
function jsThreatScan() {
  try {
  if (!chrome.runtime?.id) return;
  chrome.storage.local.get(DEFAULT_SETTINGS, (settings) => {
    if (!settings.jsThreatScan) return;

    const scripts = document.querySelectorAll('script[src]');
    const threats = [];
    const currentBase = getBaseDomain(location.hostname);

    for (const s of scripts) {
      const src = s.getAttribute('src');
      if (!src) continue;
      let url;
      try { url = new URL(src, location.href); } catch { continue; }

      const isExternal = getBaseDomain(url.hostname) !== currentBase;
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
  } catch {}
}
setTimeout(jsThreatScan, 3000);

// =============================================
// DARK PATTERN DETECTOR — sneaky UI tricks
// =============================================
function detectDarkPatterns() {
  try {
  if (!chrome.runtime?.id) return;
  chrome.storage.local.get(DEFAULT_SETTINGS, (settings) => {
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
  } catch {}
}
setTimeout(detectDarkPatterns, 4000);

// =============================================
// BREACH CHECK — check passwords in storage via HIBP Pwned Passwords API
// =============================================
let _breachCheckDone = false;
function breachCheck() {
  try {
  if (_breachCheckDone) return;
  if (!chrome.runtime?.id) return;
  chrome.storage.local.get(DEFAULT_SETTINGS, (settings) => {
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
  } catch {}
}
setTimeout(breachCheck, 5000);

// =============================================
// TAB-NAPPING PROTECTION (link hardening)
// =============================================
function hardenLinks() {
  try {
  if (!chrome.runtime?.id) return;
  chrome.storage.local.get(DEFAULT_SETTINGS, (settings) => {
    if (!settings.antiTabNapping) return;
    const links = document.querySelectorAll('a[target="_blank"]:not([rel*="noopener"])');
    for (const a of links) {
      const rel = (a.getAttribute('rel') || '').trim();
      a.setAttribute('rel', rel ? rel + ' noopener noreferrer' : 'noopener noreferrer');
    }
  });
  } catch {}
}
setTimeout(hardenLinks, 1000);
setTimeout(hardenLinks, 3000);

// =============================================
// BLOCK javascript: LINKS (DOM cleanup)
// =============================================
function neutralizeJavascriptLinks() {
  try {
  if (!chrome.runtime?.id) return;
  chrome.storage.local.get(DEFAULT_SETTINGS, (settings) => {
    if (!settings.blockJavascriptUrls) return;
    const jsLinks = document.querySelectorAll('a[href^="javascript:" i]');
    let count = 0;
    for (const a of jsLinks) {
      a.setAttribute('data-tg-blocked-href', a.getAttribute('href'));
      a.setAttribute('href', '#');
      count++;
    }
    if (count > 0) {
      chrome.runtime.sendMessage({
        action: 'jsUrlBlocked',
        detail: { count, timestamp: Date.now() }
      }).catch(() => {});
    }
  });
  } catch {}
}
setTimeout(neutralizeJavascriptLinks, 1500);
setTimeout(neutralizeJavascriptLinks, 4000);

// =============================================
// BLOCK data:/blob: IFRAMES (DOM cleanup)
// =============================================
function blockDataBlobIframes() {
  try {
  if (!chrome.runtime?.id) return;
  chrome.storage.local.get(DEFAULT_SETTINGS, (settings) => {
    if (!settings.blockDataIframes) return;
    const iframes = document.querySelectorAll('iframe[src]');
    let blocked = 0;
    for (const iframe of iframes) {
      const src = (iframe.getAttribute('src') || '').trim().toLowerCase();
      if ((src.startsWith('data:') || src.startsWith('blob:'))
          && !src.startsWith('data:image/')
          && !src.startsWith('data:application/pdf')) {
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
  } catch {}
}
setTimeout(blockDataBlobIframes, 1000);
setTimeout(blockDataBlobIframes, 3000);

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
        const currentBase = location.hostname.split('.').slice(-2).join('.');
        const targetBase = target.hostname.split('.').slice(-2).join('.');
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

// Слушаем запросы
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scan') {
    sendResponse({ findings: scanStorage(), url: location.href });
  } else if (request.action === 'removeItem') {
    try {
      if (request.storage === 'cookie') {
        // Delete cookie by setting expiry in the past
        document.cookie = request.key + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
        document.cookie = request.key + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=' + location.hostname;
        sendResponse({ success: true });
      } else {
        const store = request.storage === 'sessionStorage' ? sessionStorage : localStorage;
        store.removeItem(request.key);
        sendResponse({ success: true });
      }
    } catch (e) { sendResponse({ success: false, error: e.message }); }
  } else if (request.action === 'detectTLS') {
    // Try to extract TLS info from Performance API
    try {
      const entries = performance.getEntriesByType('resource');
      const navEntry = performance.getEntriesByType('navigation')[0];
      let info = { keyExchange: null, cipher: null, protocol: null };

      // Check if browser exposes nextHopProtocol
      if (navEntry && navEntry.nextHopProtocol) {
        info.protocol = navEntry.nextHopProtocol; // "h2", "h3", "http/1.1"
        // h3 = HTTP/3 over QUIC — always uses TLS 1.3
        if (navEntry.nextHopProtocol === 'h3') {
          info.protocol = 'HTTP/3 (QUIC + TLS 1.3)';
        } else if (navEntry.nextHopProtocol === 'h2') {
          info.protocol = 'HTTP/2 (TLS 1.2+)';
        }
      }
      sendResponse(info);
    } catch { sendResponse(null); }
    return true;
  } else if (request.action === 'auditPage') {
    sendResponse(auditPage());
  } else if (request.action === 'settingsUpdated') {
    // injected.js picks changes up via chrome.storage.onChanged in settings-preload.js
    sendResponse({ ok: true });
  }
  return true;
});
