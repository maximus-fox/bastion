/**
 * Bastion — Default settings
 * Single source of truth, loaded by the service worker (importScripts),
 * ISOLATED-world content scripts and extension pages.
 */
const DEFAULT_SETTINGS = Object.freeze({
  // Off by default: deleting site data or rewriting links breaks sites
  // (logouts, ASP.NET __doPostBack, hash routers) without the user asking.
  autoDeleteExpired: false, blockJavascriptUrls: false,
  blockExfil: true,
  antiFingerprint: true, formSpy: true, antiMiner: true,
  antiPhishing: true, blockTrackers: true,
  hideCookieBanners: true, antiWebRTC: true,
  antiKeylogger: true, antiTabNapping: true,
  clipboardGuard: true,
  jsThreatScan: true, darkPatternDetect: true, breachCheck: true,
  blockDataIframes: true
});
