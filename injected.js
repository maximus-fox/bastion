/**
 * TokenGuard — Injected Script (MAIN world)
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
    console.log(`[Bastion] ${settings.blockExfil ? 'BLOCKED' : 'Detected'} token exfiltration`, detail);
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
      // Anti-chunking: check if a significant portion of the token is in the string
      // JWT has 3 parts separated by dots. If any FULL part is in a cross-origin request, flag it.
      if (token.length > 50) {
        const parts = token.split('.');
        for (const part of parts) {
          // JWT header (part[0]) is often generic, so only check payload+signature (parts[1], parts[2])
          if (part.length > 20 && str.includes(part)) return true;
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
        // Check headers for stored tokens
        if (init && init.headers) {
          const hs = typeof init.headers === 'object'
            ? JSON.stringify(Object.fromEntries(init.headers instanceof Headers ? init.headers.entries() : Object.entries(init.headers)))
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
    if (this._tgCross) this._tgH += n + ':' + v + '\n';
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
  // 2. ANTI-FINGERPRINT (Canvas, WebGL, AudioContext)
  // =============================================
  let fpCount = 0;

  function reportFingerprint(method) {
    fpCount++;
    notify('TG_FINGERPRINT', { method, count: fpCount, timestamp: Date.now() });
  }

  // Auto-add willReadFrequently to all 2d canvas contexts
  const origGetContext = HTMLCanvasElement.prototype.getContext;
  HTMLCanvasElement.prototype.getContext = function (type, attrs) {
    if (type === '2d') {
      attrs = Object.assign({}, attrs || {}, { willReadFrequently: true });
    }
    return origGetContext.call(this, type, attrs);
  };

  // Canvas fingerprint protection — inject noise into non-transparent pixels
  let _inNoiseInjection = false; // prevent recursion between addCanvasNoise and getImageData patch
  function addCanvasNoise(canvas) {
    try {
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      if (!ctx) return;
      const w = Math.min(canvas.width, 64);
      const h = Math.min(canvas.height, 64);
      _inNoiseInjection = true;
      const img = ctx.getImageData(0, 0, w, h);
      _inNoiseInjection = false;
      const d = img.data;
      let modified = 0;
      // Walk pixels, find non-transparent ones and add subtle noise
      for (let i = 0; i < d.length && modified < 10; i += 4) {
        if (d[i + 3] > 0) { // alpha > 0 — visible pixel
          const channel = i + (modified % 3); // rotate R, G, B
          const noise = 1 + Math.floor(Math.random() * 2); // 1 or 2
          d[channel] = (d[channel] + noise) % 256;
          modified++;
        }
      }
      if (modified > 0) {
        ctx.putImageData(img, 0, 0);
      }
    } catch {}
  }

  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function () {
    if (settings.antiFingerprint && this.width > 0 && this.height > 0) {
      addCanvasNoise(this);
      reportFingerprint('canvas.toDataURL');
    }
    return origToDataURL.apply(this, arguments);
  };

  const origToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function () {
    if (settings.antiFingerprint && this.width > 0 && this.height > 0) {
      addCanvasNoise(this);
      reportFingerprint('canvas.toBlob');
    }
    return origToBlob.apply(this, arguments);
  };

  // getImageData fingerprint protection — sites hash raw pixels instead of toDataURL
  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function () {
    const imageData = origGetImageData.apply(this, arguments);
    if (!_inNoiseInjection && settings.antiFingerprint && imageData && imageData.data && imageData.data.length > 0) {
      const d = imageData.data;
      let modified = 0;
      for (let i = 0; i < d.length && modified < 10; i += 4) {
        if (d[i + 3] > 0) {
          const channel = i + (modified % 3);
          d[channel] = (d[channel] + 1 + Math.floor(Math.random() * 2)) % 256;
          modified++;
        }
      }
    }
    return imageData;
  };

  // OffscreenCanvas fingerprint protection
  if (typeof OffscreenCanvas !== 'undefined') {
    const origOCToBlob = OffscreenCanvas.prototype.convertToBlob;
    if (origOCToBlob) {
      OffscreenCanvas.prototype.convertToBlob = function () {
        if (settings.antiFingerprint && this.width > 0 && this.height > 0) {
          try {
            const ctx = this.getContext('2d');
            if (ctx) {
              const img = ctx.getImageData(0, 0, Math.min(this.width, 64), Math.min(this.height, 64));
              // noise already injected by getImageData patch above
            }
          } catch {}
          reportFingerprint('offscreen.convertToBlob');
        }
        return origOCToBlob.apply(this, arguments);
      };
    }
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
  const _gpuProfile = _gpuSet[Math.floor(Math.random() * _gpuSet.length)];

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

  const origGetParam = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function (param) {
    if (settings.antiFingerprint && param in _glParamSpoof) {
      reportFingerprint('webgl.param.' + param.toString(16));
      return _glParamSpoof[param];
    }
    return origGetParam.apply(this, arguments);
  };

  // WebGL2
  if (window.WebGL2RenderingContext) {
    const origGetParam2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function (param) {
      if (settings.antiFingerprint && param in _glParamSpoof) {
        reportFingerprint('webgl2.param.' + param.toString(16));
        return _glParamSpoof[param];
      }
      return origGetParam2.apply(this, arguments);
    };
  }

  // WebGL readPixels noise — changes WebGL image hash
  const origReadPixels = WebGLRenderingContext.prototype.readPixels;
  WebGLRenderingContext.prototype.readPixels = function () {
    origReadPixels.apply(this, arguments);
    if (settings.antiFingerprint && arguments[6] && arguments[6].length) {
      const pixels = arguments[6];
      for (let i = 0; i < pixels.length; i += 4) {
        if (pixels[i + 3] > 0) pixels[i] = (pixels[i] + 1) & 0xFF;
      }
    }
  };
  if (window.WebGL2RenderingContext) {
    const origReadPixels2 = WebGL2RenderingContext.prototype.readPixels;
    WebGL2RenderingContext.prototype.readPixels = function () {
      origReadPixels2.apply(this, arguments);
      if (settings.antiFingerprint && arguments[6] && arguments[6].length) {
        const pixels = arguments[6];
        for (let i = 0; i < pixels.length; i += 4) {
          if (pixels[i + 3] > 0) pixels[i] = (pixels[i] + 1) & 0xFF;
        }
      }
    };
  }

  // Hardware fingerprint protection — spoof CPU, RAM, screen, color depth
  if (settings.antiFingerprint) {
    // CPU cores: random 4 or 8
    const fakeCores = [4, 8][Math.floor(Math.random() * 2)];
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => fakeCores });

    // Device memory: 8 GB (most common)
    if ('deviceMemory' in navigator) {
      Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
    }

    // Screen resolution: spoof to common 1920x1080
    const fakeScreen = { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 };
    for (const [key, val] of Object.entries(fakeScreen)) {
      try { Object.defineProperty(screen, key, { get: () => val }); } catch {}
    }

    // Window inner/outer size — consistent with spoofed screen
    try {
      Object.defineProperty(window, 'outerWidth', { get: () => 1920 });
      Object.defineProperty(window, 'outerHeight', { get: () => 1040 });
    } catch {}
  }

  // AudioContext fingerprint protection
  if (window.AudioContext || window.webkitAudioContext) {
    const ACtx = window.AudioContext || window.webkitAudioContext;
    const origCreateOscillator = ACtx.prototype.createOscillator;
    const origCreateAnalyser = ACtx.prototype.createAnalyser;

    // Отслеживаем создание AudioContext для fingerprinting
    const origGetFloatFreq = AnalyserNode.prototype.getFloatFrequencyData;
    AnalyserNode.prototype.getFloatFrequencyData = function (arr) {
      const result = origGetFloatFreq.apply(this, arguments);
      if (settings.antiFingerprint && arr && arr.length > 0) {
        // Добавляем микро-шум
        arr[0] += (Math.random() - 0.5) * 0.0001;
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
      console.log('[Bastion] BLOCKED form with sensitive data submitting to cross-origin!', detail);
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
            console.log('[Bastion] BLOCKED form.submit() with sensitive data to cross-origin!', action);
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

  const OrigWorker = window.Worker;
  window.Worker = function (url, opts) {
    const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.href : '';

    if (settings.antiMiner) {
      for (const pat of MINER_PATTERNS) {
        if (pat.test(urlStr)) {
          console.log('[Bastion] BLOCKED crypto miner Worker!', urlStr);
          notify('TG_MINER_BLOCK', { url: urlStr, timestamp: Date.now() });
          // Возвращаем dummy worker
          const blob = new Blob([''], { type: 'application/javascript' });
          return new OrigWorker(URL.createObjectURL(blob), opts);
        }
      }
    }
    return new OrigWorker(url, opts);
  };
  window.Worker.prototype = OrigWorker.prototype;

  // Также проверяем SharedWorker
  if (window.SharedWorker) {
    const OrigSharedWorker = window.SharedWorker;
    window.SharedWorker = function (url, opts) {
      const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.href : '';
      if (settings.antiMiner) {
        for (const pat of MINER_PATTERNS) {
          if (pat.test(urlStr)) {
            console.log('[Bastion] BLOCKED crypto miner SharedWorker!', urlStr);
            notify('TG_MINER_BLOCK', { url: urlStr, timestamp: Date.now() });
            const blob = new Blob([''], { type: 'application/javascript' });
            return new OrigSharedWorker(URL.createObjectURL(blob), opts);
          }
        }
      }
      return new OrigSharedWorker(url, opts);
    };
    window.SharedWorker.prototype = OrigSharedWorker.prototype;
  }

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
        // Blob body — sendBeacon is sync so we can't async-read Blob,
        // but we can block ALL cross-origin sendBeacon with Blob body when blockExfil is on
        if (data instanceof Blob && settings.blockExfil && getStoredTokens().size > 0) {
          alertExfil('sendBeacon', url, 'body(blob)');
          return false;
        }
      }
    } catch {}
    return origSendBeacon.apply(navigator, arguments);
  };

  // =============================================
  // 5b. ANTI-EXFIL: WebSocket
  // =============================================
  if (window.WebSocket) {
    const OrigWebSocket = window.WebSocket;
    const origWsSend = OrigWebSocket.prototype.send;

    window.WebSocket = function (url, protocols) {
      const ws = new OrigWebSocket(url, protocols);
      const wsUrl = String(url);
      const isCross = isCrossOrigin(wsUrl.replace(/^wss?:/, 'https:'));

      if (isCross) {
        // Check URL itself
        if (containsStoredToken(wsUrl)) {
          alertExfil('websocket', wsUrl, 'url');
        }
        // Intercept send to check outgoing data (string, ArrayBuffer, Blob)
        const _origSend = ws.send.bind(ws);
        ws.send = function (data) {
          try {
            let dataStr = '';
            if (typeof data === 'string') dataStr = data;
            else if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
              try { dataStr = new TextDecoder().decode(data); } catch {}
            }
            if (dataStr && containsStoredToken(dataStr)) {
              const block = alertExfil('websocket', wsUrl, 'body');
              if (block) return; // silently drop
            }
            // Blob — can't read sync, but block large Blobs to suspicious WS when blockExfil is on
            if (data instanceof Blob && settings.blockExfil && getStoredTokens().size > 0 && data.size > 20) {
              alertExfil('websocket', wsUrl, 'body(blob)');
              return; // block all Blob sends on cross-origin WS when tokens exist
            }
          } catch {}
          return _origSend(data);
        };
      }
      return ws;
    };
    window.WebSocket.prototype = OrigWebSocket.prototype;
    window.WebSocket.CONNECTING = OrigWebSocket.CONNECTING;
    window.WebSocket.OPEN = OrigWebSocket.OPEN;
    window.WebSocket.CLOSING = OrigWebSocket.CLOSING;
    window.WebSocket.CLOSED = OrigWebSocket.CLOSED;
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

  // Also catch setAttribute('src', ...)
  const origSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    try {
      if (name === 'src' || name === 'href') {
        const url = String(value);
        // Block javascript: URLs via setAttribute
        if (name === 'href' && settings.blockJavascriptUrls
            && typeof value === 'string' && value.trim().toLowerCase().startsWith('javascript:')) {
          return origSetAttribute.call(this, 'href', '#');
        }
        // Block data:/blob: iframe src via setAttribute
        if (name === 'src' && this.tagName === 'IFRAME' && settings.blockDataIframes) {
          const v = String(value).trim().toLowerCase();
          if ((v.startsWith('data:') || v.startsWith('blob:'))
              && !v.startsWith('data:image/') && !v.startsWith('data:application/pdf')) {
            notify('TG_DATA_IFRAME_BLOCK', {
              type: 'TG_DATA_IFRAME_BLOCK', src: value.substring(0, 100), timestamp: Date.now()
            });
            return;
          }
        }
        if (isCrossOrigin(url) && containsStoredToken(url)) {
          const tag = this.tagName ? this.tagName.toLowerCase() : 'unknown';
          const block = alertExfil(tag + '.' + name, url, 'url');
          if (block) return;
        }
      }
    } catch {}
    try { return origSetAttribute.apply(this, arguments); } catch {};
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
      console.log('[Bastion] Blocked iframe srcdoc with storage access (clean API bypass)');
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
          console.log('[Bastion] Blocked iframe srcdoc with storage access');
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
  function patchIframeApis(iframe) {
    try {
      if (!iframe.contentWindow) return;

      // Patch getContext inside iframe to auto-add willReadFrequently
      try {
        const iframeCanvas = iframe.contentWindow.HTMLCanvasElement;
        if (iframeCanvas && iframeCanvas.prototype) {
          const iOrigGetContext = iframeCanvas.prototype.getContext;
          iframeCanvas.prototype.getContext = function (type, attrs) {
            if (type === '2d') {
              attrs = Object.assign({}, attrs || {}, { willReadFrequently: true });
            }
            return iOrigGetContext.call(this, type, attrs);
          };

          const iOrigToDataURL = iframeCanvas.prototype.toDataURL;
          iframeCanvas.prototype.toDataURL = function () {
            if (settings.antiFingerprint && this.width > 0 && this.height > 0) {
              try {
                const ctx = this.getContext('2d', { willReadFrequently: true });
                if (ctx) {
                  const w = Math.min(this.width, 64);
                  const h = Math.min(this.height, 64);
                  const img = ctx.getImageData(0, 0, w, h);
                  const d = img.data;
                  let mod = 0;
                  for (let i = 0; i < d.length && mod < 10; i += 4) {
                    if (d[i + 3] > 0) {
                      d[i + (mod % 3)] = (d[i + (mod % 3)] + 1 + Math.floor(Math.random() * 2)) % 256;
                      mod++;
                    }
                  }
                  if (mod > 0) ctx.putImageData(img, 0, 0);
                }
              } catch {}
              reportFingerprint('iframe.canvas.toDataURL');
            }
            return iOrigToDataURL.apply(this, arguments);
          };

          const iOrigToBlob = iframeCanvas.prototype.toBlob;
          iframeCanvas.prototype.toBlob = function () {
            if (settings.antiFingerprint && this.width > 0 && this.height > 0) {
              try {
                const ctx = this.getContext('2d', { willReadFrequently: true });
                if (ctx) {
                  const w = Math.min(this.width, 64);
                  const h = Math.min(this.height, 64);
                  const img = ctx.getImageData(0, 0, w, h);
                  const d = img.data;
                  let mod = 0;
                  for (let i = 0; i < d.length && mod < 10; i += 4) {
                    if (d[i + 3] > 0) {
                      d[i + (mod % 3)] = (d[i + (mod % 3)] + 1 + Math.floor(Math.random() * 2)) % 256;
                      mod++;
                    }
                  }
                  if (mod > 0) ctx.putImageData(img, 0, 0);
                }
              } catch {}
              reportFingerprint('iframe.canvas.toBlob');
            }
            return iOrigToBlob.apply(this, arguments);
          };
        }

        // Patch getImageData inside iframe
        const iframeCtx = iframe.contentWindow.CanvasRenderingContext2D;
        if (iframeCtx && iframeCtx.prototype) {
          const iOrigGetImageData = iframeCtx.prototype.getImageData;
          iframeCtx.prototype.getImageData = function () {
            const imageData = iOrigGetImageData.apply(this, arguments);
            if (settings.antiFingerprint && imageData && imageData.data && imageData.data.length > 0) {
              const d = imageData.data;
              let mod = 0;
              for (let i = 0; i < d.length && mod < 10; i += 4) {
                if (d[i + 3] > 0) {
                  d[i + (mod % 3)] = (d[i + (mod % 3)] + 1 + Math.floor(Math.random() * 2)) % 256;
                  mod++;
                }
              }
            }
            return imageData;
          };
        }

        // Patch WebGL inside iframe
        const iframeWebGL = iframe.contentWindow.WebGLRenderingContext;
        if (iframeWebGL && iframeWebGL.prototype) {
          const iOrigGetParam = iframeWebGL.prototype.getParameter;
          iframeWebGL.prototype.getParameter = function (param) {
            if (settings.antiFingerprint && param in _glParamSpoof) return _glParamSpoof[param];
            return iOrigGetParam.apply(this, arguments);
          };
        }
      } catch {} // cross-origin iframe will throw

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
        if (node.querySelectorAll) {
          for (const iframe of node.querySelectorAll('iframe')) {
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
  // Throttle: pause/resume every 3s to save CPU on SPA sites while still catching late iframes
  let _iframeObserverActive = true;
  setInterval(() => {
    if (_iframeObserverActive) {
      _iframePatchObserver.disconnect();
      _iframeObserverActive = false;
    } else {
      _iframePatchObserver.observe(document.documentElement, { childList: true, subtree: true });
      _iframeObserverActive = true;
    }
  }, 3000);

  // =============================================
  // 5e. ANTI-EXFIL: EventSource (SSE) & <a ping>
  // =============================================
  if (window.EventSource) {
    const OrigEventSource = window.EventSource;
    window.EventSource = function (url, opts) {
      try {
        if (isCrossOrigin(url) && containsStoredToken(String(url))) {
          const block = alertExfil('eventsource', url, 'url');
          if (block) throw new Error('[Bastion] Blocked');
        }
      } catch (e) { if (e.message.startsWith('[Bastion]')) throw e; }
      return new OrigEventSource(url, opts);
    };
    window.EventSource.prototype = OrigEventSource.prototype;
  }

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
          console.log('[Bastion] Blocked cross-origin ServiceWorker registration:', url);
          notify('TG_EXFIL_ALERT', {
            type: 'TG_EXFIL_ALERT', method: 'serviceWorker.register', url: url.substring(0, 200),
            where: 'url', timestamp: Date.now(), blocked: true
          });
          return Promise.reject(new Error('[Bastion] Blocked cross-origin ServiceWorker'));
        }
        // Log same-origin SW registration for visibility
        console.log('[Bastion] ServiceWorker registered:', url);
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

  const origAppendChild = Node.prototype.appendChild;
  Node.prototype.appendChild = function (child) {
    checkNodeForTokenUrls(child);
    return origAppendChild.call(this, child);
  };

  const origInsertBefore = Node.prototype.insertBefore;
  Node.prototype.insertBefore = function (child, ref) {
    checkNodeForTokenUrls(child);
    return origInsertBefore.call(this, child, ref);
  };

  // =============================================
  // 5k. ANTI-EXFIL: Notification icon exfiltration
  // =============================================
  if (window.Notification) {
    const OrigNotification = window.Notification;
    window.Notification = function (title, options) {
      if (options && options.icon) {
        try {
          const url = String(options.icon);
          if (isCrossOrigin(url) && containsStoredToken(url)) {
            const block = alertExfil('notification.icon', url, 'url');
            if (block) { options = { ...options, icon: undefined }; }
          }
        } catch {}
      }
      if (options && options.image) {
        try {
          const url = String(options.image);
          if (isCrossOrigin(url) && containsStoredToken(url)) {
            const block = alertExfil('notification.image', url, 'url');
            if (block) { options = { ...options, image: undefined }; }
          }
        } catch {}
      }
      return new OrigNotification(title, options);
    };
    window.Notification.prototype = OrigNotification.prototype;
    window.Notification.permission = OrigNotification.permission;
    window.Notification.requestPermission = OrigNotification.requestPermission.bind(OrigNotification);
  }

  // =============================================
  // 5l. ANTI-MINER: Blob Worker CPU monitoring
  // =============================================
  // Extend the existing Worker patch to also monitor Blob URL workers
  const _OrigWorkerRef = OrigWorker; // already saved above
  const _monitoredWorkers = new Set();

  function monitorWorkerCPU(worker, urlStr) {
    if (!settings.antiMiner) return;
    _monitoredWorkers.add(worker);
    // Check if the main thread gets sluggish (miner symptom)
    let highCpuCount = 0;
    const check = setInterval(() => {
      if (!_monitoredWorkers.has(worker)) { clearInterval(check); return; }
      const start = performance.now();
      // requestIdleCallback gives us deadline — if no idle time, CPU is busy
      requestIdleCallback((deadline) => {
        const idle = deadline.timeRemaining();
        if (idle < 2) { // Less than 2ms idle = CPU starved
          highCpuCount++;
          if (highCpuCount >= 5) { // 5 consecutive checks with no idle time
            console.log('[Bastion] Suspected crypto miner Worker (high CPU)!', urlStr);
            notify('TG_MINER_BLOCK', { url: urlStr, type: 'cpu_hog', timestamp: Date.now() });
            try { worker.terminate(); } catch {}
            _monitoredWorkers.delete(worker);
            clearInterval(check);
          }
        } else {
          highCpuCount = Math.max(0, highCpuCount - 1);
        }
      });
    }, 3000); // Check every 3 seconds
    // Auto-stop monitoring after 120 seconds if no issues
    setTimeout(() => { _monitoredWorkers.delete(worker); clearInterval(check); }, 120000);
  }

  // Re-patch Worker to add CPU monitoring for Blob workers
  const _prevWorkerPatch = window.Worker;
  window.Worker = function (url, opts) {
    const worker = _prevWorkerPatch(url, opts);
    const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.href : '';
    // Monitor Blob URL workers (can't pattern-match their content)
    if (urlStr.startsWith('blob:') && settings.antiMiner) {
      monitorWorkerCPU(worker, urlStr);
    }
    return worker;
  };
  window.Worker.prototype = _OrigWorkerRef.prototype;

  // =============================================
  // 6. ANTI-WEBRTC — Prevent IP leaks via STUN
  // =============================================
  if (window.RTCPeerConnection) {
    const OrigRTC = window.RTCPeerConnection;

    function sanitizeRTCConfig(config) {
      if (!config) config = { iceServers: [] };
      else if (!config.iceServers) config.iceServers = [];
      else {
        config.iceServers = config.iceServers.filter(server => {
          const urls = Array.isArray(server.urls) ? server.urls : [server.urls || server.url || ''];
          const hasOnlyStun = urls.every(u => typeof u === 'string' && u.startsWith('stun:'));
          if (hasOnlyStun) {
            console.log('[Bastion] Blocked STUN server (IP leak protection):', urls);
            notify('TG_WEBRTC_BLOCK', { type: 'TG_WEBRTC_BLOCK', urls, timestamp: Date.now() });
            return false;
          }
          return true;
        });
      }
      return config;
    }

    // Filter host/srflx ICE candidates from SDP to prevent real IP leak
    function filterSDP(sdp) {
      if (!sdp) return sdp;
      return sdp.replace(/a=candidate:.*typ (host|srflx).*\r?\n/g, '');
    }

    window.RTCPeerConnection = function (config, constraints) {
      if (settings.antiWebRTC) config = sanitizeRTCConfig(config);
      const pc = new OrigRTC(config, constraints);
      if (settings.antiWebRTC) {
        // Patch setLocalDescription to filter real IP from SDP
        const origSetLocal = pc.setLocalDescription.bind(pc);
        pc.setLocalDescription = function (desc) {
          if (settings.antiWebRTC && desc && desc.sdp) {
            desc = { type: desc.type, sdp: filterSDP(desc.sdp) };
          }
          return origSetLocal(desc);
        };
      }
      return pc;
    };
    window.RTCPeerConnection.prototype = OrigRTC.prototype;
    Object.keys(OrigRTC).forEach(k => { window.RTCPeerConnection[k] = OrigRTC[k]; });
  }

  // Also handle the webkit-prefixed version
  if (window.webkitRTCPeerConnection) {
    const OrigWebkitRTC = window.webkitRTCPeerConnection;
    window.webkitRTCPeerConnection = function (config, constraints) {
      if (settings.antiWebRTC) {
        if (!config) config = { iceServers: [] };
        else if (!config.iceServers) config.iceServers = [];
        else {
          config.iceServers = config.iceServers.filter(server => {
            const urls = Array.isArray(server.urls) ? server.urls : [server.urls || server.url || ''];
            return !urls.every(u => typeof u === 'string' && u.startsWith('stun:'));
          });
        }
      }
      return new OrigWebkitRTC(config, constraints);
    };
    window.webkitRTCPeerConnection.prototype = OrigWebkitRTC.prototype;
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
        console.log('[Bastion] Suspicious keylogger pattern detected!', {
          keyCount: _keyListenerCount, inputCount: _inputListenerCount,
          perElementCount: _perElementKeyCount, reason, event: type
        });
        notify('TG_KEYLOGGER_DETECT', {
          type: 'TG_KEYLOGGER_DETECT',
          keyCount: _keyListenerCount, inputCount: _inputListenerCount,
          perElementCount: _perElementKeyCount, reason, event: type, timestamp: Date.now()
        });
      }
      // After detection: block new keydown/keyup listeners on individual inputs
      if (_keyloggerReported && !isGlobal && RAW_KEY_EVENTS.includes(type)
          && this instanceof HTMLElement
          && (this.tagName === 'INPUT' || this.tagName === 'TEXTAREA')) {
        console.log('[Bastion] Blocked keylogger listener on', this.tagName);
        return; // don't attach the listener
      }
    }
    return origAddEventListener.apply(this, arguments);
  };

  // =============================================
  // 6b. ANTI-EXFIL: window.name data channel protection
  // =============================================
  // window.name persists across navigations — attacker sets it to token, navigates to evil.com
  const windowNameDesc = Object.getOwnPropertyDescriptor(window, 'name') ||
    { set: (v) => {}, get: () => '', configurable: true, enumerable: true };
  try {
    let _windowName = window.name || '';
    Object.defineProperty(window, 'name', {
      configurable: true,
      enumerable: true,
      get() { return _windowName; },
      set(val) {
        const str = String(val);
        if (containsStoredToken(str)) {
          console.log('[Bastion] Blocked token in window.name (cross-origin data channel)');
          notify('TG_EXFIL_ALERT', {
            type: 'TG_EXFIL_ALERT', method: 'window.name', url: location.href,
            where: 'name', timestamp: Date.now(), blocked: settings.blockExfil
          });
          if (settings.blockExfil) return;
        }
        _windowName = str;
      }
    });
  } catch {}

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
    if (!text || text.length < 20 || text.length > 70) return null;
    const trimmed = text.trim();
    for (const c of CRYPTO_PATTERNS) {
      if (c.pattern.test(trimmed)) return c.name;
    }
    return null;
  }

  // Track what user copies vs what gets written
  let _lastUserCopy = null;
  let _lastCopyTime = 0;

  // Intercept clipboard write
  if (navigator.clipboard && navigator.clipboard.writeText) {
    const origWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = function (text) {
      if (settings.clipboardGuard) {
        const cryptoType = isCryptoAddress(text);
        // If something is writing a crypto address that differs from what user copied
        if (cryptoType && _lastUserCopy && _lastUserCopy !== text && Date.now() - _lastCopyTime < 10000) {
          const origCrypto = isCryptoAddress(_lastUserCopy);
          if (origCrypto) {
            // Crypto address swap detected!
            console.warn('[Bastion] CLIPBOARD SWAP BLOCKED!', { original: _lastUserCopy, swapped: text });
            notify('TG_CLIPBOARD_SWAP', {
              type: 'TG_CLIPBOARD_SWAP',
              original: _lastUserCopy.substring(0, 20) + '...',
              swapped: text.substring(0, 20) + '...',
              cryptoType,
              timestamp: Date.now(),
              blocked: true
            });
            // Write the ORIGINAL address, not the swapped one
            return origWriteText(_lastUserCopy);
          }
        }
        // Track this write as potential user copy
        _lastUserCopy = text;
        _lastCopyTime = Date.now();
      }
      return origWriteText(text);
    };
  }

  // Track user copy events (selection + Ctrl+C / Cmd+C)
  document.addEventListener('copy', () => {
    if (!settings.clipboardGuard) return;
    try {
      const selection = window.getSelection();
      if (selection && selection.toString().trim()) {
        _lastUserCopy = selection.toString().trim();
        _lastCopyTime = Date.now();
      }
    } catch {}
  }, true);

  // Intercept old-style document.execCommand('copy')
  const origExecCommand = document.execCommand.bind(document);
  document.execCommand = function (cmd, ...args) {
    if (settings.clipboardGuard && cmd === 'copy') {
      try {
        const selection = window.getSelection();
        if (selection && selection.toString().trim()) {
          _lastUserCopy = selection.toString().trim();
          _lastCopyTime = Date.now();
        }
      } catch {}
    }
    return origExecCommand(cmd, ...args);
  };

  // Intercept binary clipboard.write() — attackers bypass writeText via ClipboardItem
  if (navigator.clipboard && navigator.clipboard.write) {
    const origWrite = navigator.clipboard.write.bind(navigator.clipboard);
    navigator.clipboard.write = function (items) {
      if (!settings.clipboardGuard || !items || !items.length) return origWrite(items);
      // Read text/plain from ClipboardItem to check for address swap
      return (async () => {
        try {
          for (const item of items) {
            if (item instanceof ClipboardItem && item.types.includes('text/plain')) {
              const blob = await item.getType('text/plain');
              const text = await blob.text();
              const cryptoType = isCryptoAddress(text);
              if (cryptoType && _lastUserCopy && _lastUserCopy !== text && Date.now() - _lastCopyTime < 10000) {
                const origCrypto = isCryptoAddress(_lastUserCopy);
                if (origCrypto) {
                  console.warn('[Bastion] CLIPBOARD SWAP BLOCKED (binary write)!', { original: _lastUserCopy, swapped: text });
                  notify('TG_CLIPBOARD_SWAP', {
                    type: 'TG_CLIPBOARD_SWAP',
                    original: _lastUserCopy.substring(0, 20) + '...',
                    swapped: text.substring(0, 20) + '...',
                    cryptoType, timestamp: Date.now(), blocked: true
                  });
                  // Replace with original address
                  const origBlob = new Blob([_lastUserCopy], { type: 'text/plain' });
                  const origItem = new ClipboardItem({ 'text/plain': origBlob });
                  return origWrite([origItem]);
                }
              }
            }
          }
        } catch {}
        return origWrite(items);
      })();
    };
  }

  // Intercept binary clipboard.read() — same bypass vector
  if (navigator.clipboard && navigator.clipboard.read) {
    const origRead = navigator.clipboard.read.bind(navigator.clipboard);
    navigator.clipboard.read = function () {
      if (!settings.clipboardGuard) return origRead();
      return origRead().then(async (items) => {
        try {
          for (let i = 0; i < items.length; i++) {
            if (items[i].types.includes('text/plain')) {
              const blob = await items[i].getType('text/plain');
              const text = await blob.text();
              const cryptoType = isCryptoAddress(text);
              if (cryptoType && _lastUserCopy && text !== _lastUserCopy && Date.now() - _lastCopyTime < 30000) {
                const origCrypto = isCryptoAddress(_lastUserCopy);
                if (origCrypto) {
                  console.warn('[Bastion] CLIPBOARD READ SWAP DETECTED (binary)!');
                  notify('TG_CLIPBOARD_SWAP', {
                    type: 'TG_CLIPBOARD_SWAP',
                    original: _lastUserCopy.substring(0, 20) + '...',
                    swapped: text.substring(0, 20) + '...',
                    cryptoType, timestamp: Date.now(), blocked: true
                  });
                  const origBlob = new Blob([_lastUserCopy], { type: 'text/plain' });
                  const origItem = new ClipboardItem({ 'text/plain': origBlob });
                  return [origItem];
                }
              }
            }
          }
        } catch {}
        return items;
      });
    };
  }

  // Intercept clipboard read to detect paste swap
  if (navigator.clipboard && navigator.clipboard.readText) {
    const origReadText = navigator.clipboard.readText.bind(navigator.clipboard);
    navigator.clipboard.readText = function () {
      if (!settings.clipboardGuard) return origReadText();
      return origReadText().then(text => {
        const cryptoType = isCryptoAddress(text);
        if (cryptoType && _lastUserCopy && text !== _lastUserCopy && Date.now() - _lastCopyTime < 30000) {
          const origCrypto = isCryptoAddress(_lastUserCopy);
          if (origCrypto) {
            console.warn('[Bastion] CLIPBOARD READ SWAP DETECTED!', { expected: _lastUserCopy, got: text });
            notify('TG_CLIPBOARD_SWAP', {
              type: 'TG_CLIPBOARD_SWAP',
              original: _lastUserCopy.substring(0, 20) + '...',
              swapped: text.substring(0, 20) + '...',
              cryptoType,
              timestamp: Date.now(),
              blocked: true
            });
            return _lastUserCopy; // Return original
          }
        }
        return text;
      });
    };
  }

  // =============================================
  // 8. TAB-NAPPING PROTECTION — Secure window.open + block background navigation
  // =============================================
  const origWindowOpen = window.open;
  window.open = function (url, target, features) {
    if (settings.antiTabNapping) {
      // Add noopener to prevent the new window from accessing window.opener
      if (features) {
        if (!features.includes('noopener')) features += ',noopener';
      } else {
        features = 'noopener';
      }
      // Also nullify opener after open
      const win = origWindowOpen.call(this, url, target, features);
      // Extra safety: if somehow opener is still set
      try { if (win) win.opener = null; } catch {}
      return win;
    }
    return origWindowOpen.apply(this, arguments);
  };

  // Block page navigation when tab is not focused (tab-napping attack)
  if (settings.antiTabNapping) {
    let _tabFocused = document.hasFocus();
    window.addEventListener('blur', () => { _tabFocused = false; });
    window.addEventListener('focus', () => { _tabFocused = true; });

    // location.assign/replace are read-only in modern browsers,
    // so we use beforeunload to warn about background navigation
    window.addEventListener('beforeunload', (e) => {
      if (!_tabFocused && settings.antiTabNapping) {
        console.log('[Bastion] Tab-napping navigation detected while tab unfocused');
        notify('TG_TABNAP_BLOCK', {
          type: 'TG_TABNAP_BLOCK', blockedUrl: location.href, timestamp: Date.now()
        });
      }
    });
  }

  // =============================================
  // 9. BLOCK javascript: URLs — Prevent XSS via links
  // =============================================
  if (settings.blockJavascriptUrls) {
    // Patch HTMLAnchorElement.prototype.href setter
    const anchorHrefDesc = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
    if (anchorHrefDesc && anchorHrefDesc.set) {
      const origAnchorHrefSet = anchorHrefDesc.set;
      Object.defineProperty(HTMLAnchorElement.prototype, 'href', {
        ...anchorHrefDesc,
        set(val) {
          if (settings.blockJavascriptUrls && typeof val === 'string'
              && val.trim().toLowerCase().startsWith('javascript:')) {
            console.log('[Bastion] Blocked javascript: URL on <a>');
            notify('TG_JS_URL_BLOCK', {
              type: 'TG_JS_URL_BLOCK', url: val.substring(0, 100), timestamp: Date.now()
            });
            origAnchorHrefSet.call(this, '#');
            return;
          }
          origAnchorHrefSet.call(this, val);
        }
      });
    }

    // Click handler — last line of defense for existing javascript: links
    document.addEventListener('click', (e) => {
      if (!settings.blockJavascriptUrls) return;
      const link = e.target.closest('a[href]');
      if (link) {
        const href = link.getAttribute('href') || '';
        if (href.trim().toLowerCase().startsWith('javascript:')) {
          e.preventDefault();
          e.stopImmediatePropagation();
          console.log('[Bastion] Blocked click on javascript: link');
          notify('TG_JS_URL_BLOCK', {
            type: 'TG_JS_URL_BLOCK', url: href.substring(0, 100), timestamp: Date.now()
          });
        }
      }
    }, true);
  }

  // =============================================
  // 10. BLOCK data:/blob: IFRAMES — Prevent phishing iframes
  // =============================================
  if (settings.blockDataIframes) {
    const iframeSrcDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
    if (iframeSrcDesc && iframeSrcDesc.set) {
      const origIframeSrcSet = iframeSrcDesc.set;
      Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
        ...iframeSrcDesc,
        set(val) {
          if (settings.blockDataIframes) {
            const v = String(val).trim().toLowerCase();
            if (v.startsWith('data:') || v.startsWith('blob:')) {
              // Allow safe types: images, pdf
              if (v.startsWith('data:image/') || v.startsWith('data:application/pdf')) {
                // safe — pass through
              } else {
                console.log('[Bastion] Blocked data:/blob: iframe:', val.substring(0, 80));
                notify('TG_DATA_IFRAME_BLOCK', {
                  type: 'TG_DATA_IFRAME_BLOCK', src: val.substring(0, 100), timestamp: Date.now()
                });
                return; // don't set src
              }
            }
          }
          origIframeSrcSet.call(this, val);
        }
      });
    }
  }
})();
