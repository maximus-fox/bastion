/**
 * TokenGuard — Settings Preloader (ISOLATED world, document_start)
 * Writes settings to DOM attribute so injected.js (MAIN world) can read them
 * BEFORE any page script executes.
 */
try {
  chrome.storage.local.get({
    blockExfil: true, antiFingerprint: true, formSpy: true,
    antiMiner: true, antiWebRTC: true, antiKeylogger: true,
    antiTabNapping: true, clipboardGuard: true,
    blockJavascriptUrls: true, blockDataIframes: true
  }, (s) => {
    try {
      document.documentElement.dataset.tgSettings = JSON.stringify(s);
    } catch {}
  });
} catch {}
