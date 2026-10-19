/**
 * Bastion — Settings bridge (ISOLATED world, document_start)
 *
 * injected.js (MAIN world) runs right after this script and before any page
 * script. It picks a random channel name and announces it with a synchronous
 * 'bastion:hello' event, so only the two extension scripts ever learn it:
 * the page can neither forge settings nor spoof protection events, and it never
 * sees the extension's configuration.
 *
 * Channel events (detail is always a JSON string — objects don't cross worlds):
 *   <channel>:settings  ISOLATED → MAIN  settings for injected.js
 *   <channel>:event     MAIN → ISOLATED  protection events, forwarded to background
 */
(() => {
  // Settings injected.js acts on; nothing else is sent into the page's world.
  const MAIN_KEYS = [
    'blockExfil', 'antiFingerprint', 'formSpy', 'antiMiner', 'antiWebRTC',
    'antiKeylogger', 'antiTabNapping', 'clipboardGuard',
    'blockJavascriptUrls', 'blockDataIframes'
  ];
  const EVENT_ACTIONS = {
    TG_EXFIL_ALERT: 'exfilAlert',
    TG_FINGERPRINT: 'fingerprintDetected',
    TG_FORM_BLOCK: 'formBlocked',
    TG_MINER_BLOCK: 'minerBlocked',
    TG_WEBRTC_BLOCK: 'webrtcBlocked',
    TG_KEYLOGGER_DETECT: 'keyloggerDetected',
    TG_CLIPBOARD_SWAP: 'clipboardSwapBlocked',
    TG_TABNAP_BLOCK: 'tabNappingBlocked',
    TG_JS_URL_BLOCK: 'jsUrlBlocked',
    TG_DATA_IFRAME_BLOCK: 'dataIframeBlocked',
  };

  let channel = null;

  function contextAlive() {
    try { return !!chrome.runtime?.id; } catch { return false; }
  }

  function sendSettings(s) {
    if (!channel) return;
    const out = {};
    for (const k of MAIN_KEYS) out[k] = s[k] !== undefined ? !!s[k] : DEFAULT_SETTINGS[k];
    document.dispatchEvent(new CustomEvent(channel + ':settings', { detail: JSON.stringify(out) }));
  }

  function loadAndSend() {
    if (!contextAlive()) return;
    chrome.storage.local.get(DEFAULT_SETTINGS, sendSettings);
  }

  function onHello(e) {
    if (channel || typeof e.detail !== 'string' || !e.detail.startsWith('bastion:')) return;
    document.removeEventListener('bastion:hello', onHello);
    channel = e.detail;

    document.addEventListener(channel + ':event', (ev) => {
      if (!contextAlive() || typeof ev.detail !== 'string') return;
      let data;
      try { data = JSON.parse(ev.detail); } catch { return; }
      const action = data && EVENT_ACTIONS[data.type];
      if (action) chrome.runtime.sendMessage({ action, detail: data }).catch(() => {});
    });

    // Defaults go out synchronously so injected.js is configured before any
    // page script runs; stored settings follow once storage answers.
    sendSettings(DEFAULT_SETTINGS);
    loadAndSend();
  }

  document.addEventListener('bastion:hello', onHello);

  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && MAIN_KEYS.some((k) => k in changes)) loadAndSend();
    });
  } catch {}
})();
