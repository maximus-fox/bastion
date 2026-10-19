/**
 * Bastion — Background Service Worker
 * Badge, Security Headers, notifications, history, tracker counter, shield events
 */

importScripts('defaults.js'); // DEFAULT_SETTINGS

const SECURITY_HEADERS = [
  'strict-transport-security', 'content-security-policy', 'x-frame-options',
  'x-content-type-options', 'x-xss-protection', 'referrer-policy'
];

// Known tracker domains: pure tracking/ads endpoints, blocked when loaded by another site
// (domainType: thirdParty). Keep out SSO, captchas, anti-bot/anti-fraud checks,
// CDNs, consent managers, support chat and content embeds: blocking those
// breaks logins, checkouts and pages.
const TRACKER_DOMAINS = [
  // =====================================================
  //  GOOGLE / ALPHABET (Global)
  // =====================================================
  'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
  'googlesyndication.com', 'googleadservices.com', 'googletagservices.com',
  'google-analytics.l.google.com', 'pagead2.googlesyndication.com',
  'adservice.google.com', 'adservice.google.ru', 'adservice.google.co.jp',
  'adservice.google.co.kr', 'adservice.google.co.in', 'adservice.google.com.br',
  'firebaselogging-pa.googleapis.com', 'app-measurement.com',
  'ad.doubleclick.net', 'cm.g.doubleclick.net', 'stats.g.doubleclick.net',
  'www.googleadservices.com', 'partner.googleadservices.com',
  'ssl.google-analytics.com', 'www.google-analytics.com',

  // =====================================================
  //  META / FACEBOOK / INSTAGRAM (Global)
  // =====================================================
  'connect.facebook.net', 'pixel.facebook.com', 'tr.facebook.com',
  'an.facebook.com', 'ads.facebook.com',
  'analytics.instagram.com',
  'pixel.instagram.com', 'business.facebook.com',
  'www.facebook.com/tr', 'ad.atdmt.com',

  // =====================================================
  //  TWITTER / X (Global)
  // =====================================================
  'analytics.twitter.com', 'ads-twitter.com', 'ads-api.twitter.com',
  'static.ads-twitter.com', 't.co',

  // =====================================================
  //  MICROSOFT / LINKEDIN / BING
  // =====================================================
  'clarity.ms', 'bat.bing.com', 'bat.r.msn.com',
  'ads.linkedin.com', 'snap.licdn.com', 'px.ads.linkedin.com',
  'analytics.pointdrive.linkedin.com',
  'dc.ads.linkedin.com', 'tr.lfeeder.com',

  // =====================================================
  //  AMAZON / AWS
  // =====================================================
  'fls-na.amazon.com', 'fls-eu.amazon.com', 'aax.amazon-adsystem.com',
  'z-na.amazon-adsystem.com', 'amazon-adsystem.com',
  'assoc-amazon.com', 'aan.amazon.com',
  'unagi.amazon.com', 'device-metrics-us.amazon.com',

  // =====================================================
  //  APPLE
  // =====================================================
  'iadsdk.apple.com', 'advertising.apple.com',
  'books-analytics-events.apple.com', 'notes-analytics-events.apple.com',
  'metrics.icloud.com', 'xp.apple.com',

  // =====================================================
  //  TIKTOK / BYTEDANCE
  // =====================================================
  'analytics.tiktok.com', 'ads-api.tiktok.com', 'mcs.tiktokw.com',
  'log.byteoversea.com', 'mon.byteoversea.com',
  'analytics-sg.tiktok.com', 'log16-sign-sg.tiktokv.com',
  'abtest-va-tiktok.byteoversea.com',

  // =====================================================
  //  SNAPCHAT
  // =====================================================
  'tr.snapchat.com', 'sc-static.net', 'sc-analytics.appspot.com',
  'ads-api.snapchat.com', 'gcp-us-east1.api.snapchat.com',

  // =====================================================
  //  PINTEREST
  // =====================================================
  'widgets.pinterest.com', 'ct.pinterest.com', 'trk.pinterest.com',
  'log.pinterest.com', 'analytics.pinterest.com',

  // =====================================================
  //  RUSSIA — Yandex, VK, Mail.ru, Rambler, Sber
  // =====================================================
  'mc.yandex.ru', 'mc.yandex.com', 'an.yandex.ru', 'yandexadexchange.net',
  'adfox.yandex.ru', 'matchid.adfox.yandex.ru', 'metrika.yandex.ru',
  'informer.yandex.ru', 'clck.yandex.ru', 'jstracer.yandex.ru',
  'yandex.ru/clck', 'awaps.yandex.ru', 'bs.yandex.ru',
  // VK / Mail.ru
  'top-fwz1.mail.ru', 'rs.mail.ru', 'top.mail.ru', 'ad.mail.ru',
  'r.mail.ru', 'pixel.mail.ru',
  'ads.vk.com', 'pixel.vk.com', 'vk.com/rtrg', 'st.vk.com/analytics',
  'tracker.vk.com', 'rating.vk.com',
  // Other RU
  'counter.yadro.ru', 'counter.rambler.ru', 'tn.smi2.net', 'smi2.ru',
  'tns-counter.ru', 'www.tns-counter.ru',
  'ad.adriver.ru', 'content.adriver.ru',
  'display.nativeroll.tv', 'nativeroll.tv',
  'betweendigital.com', 'relap.io', 'buzzoola.com',
  // RU Banks trackers
  'mc.bankiros.ru', 'click.alfabank.ru', 'smetrics.sberbank.ru',
  'analytics.tinkoff.ru', 'tracking.vtb.ru',

  // =====================================================
  //  CHINA — Baidu, Alibaba, Tencent, Sina, JD, Douyin
  // =====================================================
  'hm.baidu.com', 'pos.baidu.com', 'cpro.baidu.com', 'eclick.baidu.com',
  'nsclick.baidu.com', 'baidustatic.com', 'hmcdn.baidu.com',
  // Alibaba
  'log.mmstat.com',
  'gm.mmstat.com', 'arms-retcode.aliyuncs.com',
  // Tencent / QQ / WeChat
  'beacon.qq.com', 'pingtas.qq.com', 'report.qq.com', 'btrace.qq.com',
  'trace.qq.com', 'pgdt.gtimg.cn', 'adservice.qq.com',
  'mp.weixin.qq.com/mp/report',
  // Sina / Weibo
  'sax.sina.com.cn', 'beacon.sina.com.cn',
  'trends.weibodata.com',
  // CNZZ / Umeng
  'cnzz.com', 'c.cnzz.com', 's4.cnzz.com', 's96.cnzz.com',
  'web.umeng.co', 'log.umsns.com', 'oc.umeng.com',
  // JD
  'wl.jd.com', 'saturn.jd.com', 'click.union.jd.com',
  // Douyin (CN TikTok)
  'log.snssdk.com', 'mon.snssdk.com', 'i.snssdk.com',

  // =====================================================
  //  SOUTH KOREA — Naver, Kakao, Coupang, Samsung
  // =====================================================
  'pixel.naver.com', 'wcs.naver.com', 'ntm.naver.com',
  'spi.naver.com', 'lcs.naver.com', 'nstat.naver.com',
  'track.kakao.com', 'pixel.kakao.com', 'kpf.kakao.com',
  'analytics.kakao.com', 'kat.kakao.com',
  'adcreative.coupang.com', 'ads.coupang.com',
  'samsungads.com', 'nmetrics.samsung.com', 'analytics.samsung.com',
  'pixel.11st.co.kr', 'log.toss.im',

  // =====================================================
  //  JAPAN — LINE, Yahoo JP, Rakuten
  // =====================================================
  'tr.line.me', 'scdn.line-apps.com',
  'yads.yahoo.co.jp', 'yjtag.yahoo.co.jp',
  'b90.yahoo.co.jp', 'retarget.yahoo.co.jp',
  'rat.rakuten.co.jp',
  'pixel.dmm.co.jp', 'ct.nikkei.com',

  // =====================================================
  //  INDIA — Flipkart, Paytm, PhonePe, Jio
  // =====================================================
  'pixel.flipkart.com', 'tracker.flipkart.com', 'ads.flipkart.com',
  'ads.jio.com', 'analytics.jio.com',
  'pixel.paytm.com', 'analytics.paytm.com',
  'pixel.phonepe.com', 'analytics.swiggy.com',
  'analytics.razorpay.com',

  // =====================================================
  //  BRAZIL — MercadoLibre, Nubank, PagSeguro
  // =====================================================
  'analytics.mercadolibre.com',
  'analytics.nubank.com.br', 'pixel.pagseguro.com',
  'analytics.b2w.io', 'analytics.americanas.com',

  // =====================================================
  //  EUROPE — Zalando, Criteo, Trade Desk
  // =====================================================
  'uk-ads.openx.net', 'pixel.rubiconproject.com', 'ib.adnxs.com',
  'tag.getdrip.com',
  'sslwidget.criteo.com', 'dis.eu.criteo.com',
  'pixel.onbuy.com', 'analytics.zalando.com',
  'tracker.klarna.com', 'pixel.klarna.com',
  'analytics.n26.com', 'analytics.revolut.com',

  // =====================================================
  //  MIDDLE EAST / TURKEY / AFRICA
  // =====================================================
  'pixel.souq.com', 'analytics.noon.com',
  'pixel.jumia.com', 'analytics.hepsiburada.com',
  'pixel.trendyol.com', 'analytics.getir.com',

  // =====================================================
  //  AD NETWORKS — Global Exchanges & SSP
  // =====================================================
  'adnxs.com', 'adsrvr.org', 'criteo.com', 'criteo.net',
  'openx.net', 'pubmatic.com', 'rubiconproject.com',
  'smartadserver.com', 'casalemedia.com', 'media.net',
  'bidswitch.net', 'sharethrough.com', 'indexexchange.com',
  'advertising.com', 'adform.net', 'adroll.com',
  'mopub.com', 'applovin.com', 'chartboost.com',
  'vungle.com', 'ironsrc.com', 'inmobi.com',
  'smaato.net', 'fyber.com', 'adcolony.com',
  'liftoff.io', 'moloco.com', 'remerge.io',
  'rtb-seller.com', 'aralego.com', 'contextweb.com',
  'yieldmo.com', 'triplelift.com', 'sovrn.com',
  'lijit.com', 'gumgum.com', 'nativo.net',
  'seedtag.com', 'teads.tv', 'undertone.com',
  'ad-stir.com', 'i-mobile.co.jp', 'zucks.co.jp',
  'adpushup.com', 'ezoic.net', 'mediavine.com',
  'raptive.com', 'playwire.com', 'sonobi.com',

  // =====================================================
  //  ANALYTICS & HEATMAPS
  // =====================================================
  'hotjar.com', 'static.hotjar.com', 'script.hotjar.com',
  'fullstory.com', 'rs.fullstory.com', 'edge.fullstory.com',
  'mixpanel.com', 'cdn.mxpnl.com', 'api-js.mixpanel.com',
  'amplitude.com', 'api.amplitude.com', 'cdn.amplitude.com',
  'segment.io', 'cdn.segment.com', 'api.segment.io',
  'mouseflow.com', 'crazyegg.com', 'optimizely.com',
  'heapanalytics.com', 'cdn.heapanalytics.com',
  'plausible.io', 'app.posthog.com', 'eu.posthog.com',
  'stats.wp.com', 'pixel.wp.com',
  'matomo.cloud', 'piwik.pro', 'getclicky.com',
  'luckyorange.com', 'inspectlet.com', 'logrocket.io',
  'smartlook.com', 'rec.smartlook.com',
  'sentry.io',
  'js.hs-analytics.net', 'js.hs-banner.com', 'track.hubspot.com',
  'cdn.branch.io', 'app.link', 'adjust.com', 'app.adjust.com',
  'app.appsflyer.com', 'launches.appsflyer.com',
  'kochava.com', 'control.kochava.com',
  'singular.net', 'sdk-api-v1.singular.net',

  // =====================================================
  //  RETARGETING & DATA BROKERS
  // =====================================================
  'taboola.com', 'outbrain.com', 'scorecardresearch.com', 'imrworldwide.com',
  'quantserve.com', 'quantcount.com', 'rlcdn.com', 'bluekai.com',
  'demdex.net', 'everesttech.net', 'krxd.net',
  'exelator.com', 'agkn.com', 'pippio.com',
  'acuityplatform.com', 'eyeota.net', 'lotame.com',
  'intentiq.com', 'id5-sync.com', 'liveintent.com',
  'liveramp.com', 'adsymptotic.com', 'bombora.com',
  'oracle.com/cx', 'addthis.com', 's7.addthis.com', 'cache.addthiscdn.com',
  'static.addtoany.com', 'sharethis.com',

  // =====================================================
  //  FINGERPRINTING & BOT DETECTION
  // =====================================================
  'fpjs.io', 'api.fpjs.io', 'cdn.fingerprint.com',
  'fingerprint.com', 'fpcdn.io', 'fpnpmcdn.net',
  'b.cdnwidget.com',
  'risk.clearbit.com', 'reveal.clearbit.com',

  // =====================================================
  //  CRYPTO & WEB3 TRACKERS
  // =====================================================
  'pixel.coinbase.com', 'analytics.coinbase.com',
  'tr.coinmarketcap.com', 'pixel.coinmarketcap.com',
  'analytics.kraken.com', 'pixel.kraken.com',
  'analytics.binance.com', 'pixel.binance.com', 'bcfin.binance.com',
  'analytics.crypto.com', 'pixel.crypto.com',
  'analytics.kucoin.com', 'pixel.bybit.com',
  'analytics.okx.com', 'pixel.okx.com',
  'analytics.gemini.com', 'analytics.bitfinex.com',
  'pixel.gate.io', 'analytics.huobi.com',
  'analytics.mexc.com', 'analytics.bitget.com',
  'tr.coingecko.com', 'pixel.coingecko.com',
  'analytics.uniswap.org', 'analytics.opensea.io',
  'analytics.metamask.io', 'pixel.phantom.app',
  'analytics.dydx.exchange', 'analytics.aave.com',
  'pixel.lido.fi', 'analytics.curve.fi',
  'vitals.vercel-insights.com', 'va.vercel-scripts.com',

  // =====================================================
  //  BANKING & FINTECH TRACKERS (Global)
  // =====================================================
  // US Banks
  'analytics.jpmorgan.com', 'pixel.chase.com',
  'analytics.bankofamerica.com', 'pixel.wellsfargo.com',
  'analytics.citi.com', 'smetrics.citi.com',
  'analytics.capitalone.com', 'events.capitalone.com',
  'analytics.goldmansachs.com', 'analytics.morganstanley.com',
  'pixel.americanexpress.com', 'analytics.discover.com',
  // EU Banks
  'analytics.wise.com', 'pixel.monzo.com',
  'analytics.hsbc.com', 'pixel.barclays.co.uk',
  'analytics.ing.com', 'analytics.deutschebank.com',
  'analytics.bnpparibas.com', 'analytics.unicredit.it',
  'analytics.santander.com', 'analytics.bbva.com',
  'analytics.ubs.com', 'analytics.credit-suisse.com',
  // RU Banks
  'analytics.alfabank.ru',
  'pixel.gazprombank.ru',
  'analytics.raiffeisen.ru', 'pixel.open.ru',
  'analytics.banki.ru',
  // India Banks
  'analytics.icicibank.com', 'pixel.hdfcbank.com',
  'analytics.axisbank.com', 'analytics.kotak.com',
  // Payment Systems
  't.paypal.com', 'pixel.paypal.com', 'analytics.paypal.com',
  'analytics.stripe.com', 'r.stripe.com', 'q.stripe.com',
  'pixel.square.com', 'analytics.squareup.com',
  'pixel.adyen.com', 'analytics.checkout.com',
  'analytics.braintreepayments.com', 'pixel.2checkout.com',
  'analytics.worldpay.com',
  'analytics.afterpay.com',
  'pixel.affirm.com',

  // =====================================================
  //  GOVERNMENT / STATE TRACKERS
  // =====================================================
  // Russia Gov
  'mc.gosuslugi.ru', 'counter.gosuslugi.ru', 'pos.gosuslugi.ru',
  'analytics.mos.ru', 'counter.mos.ru', 'pixel.mos.ru',
  'analytics.government.ru', 'mc.nalog.gov.ru',
  'analytics.pfr.gov.ru', 'analytics.rosreestr.gov.ru',
  'counter.zakupki.gov.ru',
  // US Gov
  'dap.digitalgov.gov', 'analytics.usa.gov',
  // EU Gov
  'analytics.ec.europa.eu', 'webanalytics.europa.eu',
  'matomo.gouvernement.fr', 'stats.service.gov.uk',
  'analytics.bundestag.de',
  // China Gov
  'tongji.gov.cn', 'analytics.gov.cn',
  // India Gov
  'analytics.india.gov.in', 'analytics.uidai.gov.in',
  // Korea Gov
  'analytics.go.kr', 'log.korea.kr',

  // =====================================================
  //  E-COMMERCE TRACKERS
  // =====================================================
  'pixel.shopify.com', 'analytics.shopify.com', 'monorail-edge.shopifysvc.com',
  'ct.shopify.com',
  'analytics.ebay.com', 'rover.ebay.com',
  'analytics.etsy.com', 'pixel.etsy.com',
  'pixel.aliexpress.com', 'analytics.aliexpress.com',
  'pixel.wish.com', 'analytics.shein.com',
  'pixel.ozon.ru', 'analytics.ozon.ru',
  'pixel.wildberries.ru', 'analytics.wildberries.ru',
  'pixel.lamoda.ru', 'analytics.dns-shop.ru',

  // =====================================================
  //  TELECOM / ISP TRACKERS
  // =====================================================
  'analytics.att.com', 'pixel.verizon.com', 'ads.verizonmedia.com',
  'pixel.t-mobile.com', 'analytics.vodafone.com',
  'analytics.orange.com', 'pixel.telefonica.com',
  'analytics.mts.ru', 'analytics.megafon.ru',
  'analytics.beeline.ru', 'analytics.tele2.ru',
  'analytics.airtel.in', 'pixel.reliance.com',
  'analytics.chinamobile.com', 'analytics.kt.com',

  // =====================================================
  //  HEALTH / PHARMA TRACKERS
  // =====================================================
  'analytics.webmd.com', 'pixel.healthline.com',
  'analytics.drugs.com', 'pixel.goodrx.com',
  'analytics.zocdoc.com', 'pixel.doctolib.fr',
  'analytics.practo.com',

  // =====================================================
  //  TRAVEL & BOOKING
  // =====================================================
  'pixel.booking.com', 'analytics.booking.com',
  'analytics.airbnb.com', 'pixel.tripadvisor.com',
  'analytics.expedia.com', 'pixel.kayak.com',
  'analytics.skyscanner.net', 'pixel.aviasales.ru',

  // =====================================================
  //  GAMING
  // =====================================================
  'analytics.steampowered.com', 'pixel.epicgames.com',
  'analytics.roblox.com', 'gameanalytics.com',
  'insights.unity3d.com', 'config.uca.cloud.unity3d.com',
  'cdp.cloud.unity3d.com', 'analytics.activision.com',

  // =====================================================
  //  MEDIA / STREAMING
  // =====================================================
  'analytics.spotify.com', 'pixel.spotify.com',
  'ichnaea.netflix.com', 'customerevents.netflix.com',
  'analytics.twitch.tv', 'spade.twitch.tv',
  'analytics.hulu.com', 'sanalytics.disneyplus.com',
  'analytics.deezer.com', 'pixel.yandex.music',
  'analytics.kinopoisk.ru',

  // =====================================================
  //  SOCIAL WIDGETS (data leaks)
  // =====================================================
  'badge.stumbleupon.com',
  'share.yandex.ru',

  // =====================================================
  //  CDN-HOSTED TRACKERS & TAG MANAGERS
  // =====================================================
  'cdn.onesignal.com', 'onesignal.com',
  'cdn.pushwoosh.com', 'cp.pushwoosh.com',
  'sdk.pushwoosh.com', 'cdn.subscribers.com',
  'push.zalo.me', 'notix.io',
  'js.hs-scripts.com',
  'js.hubspot.com',
  'pixel.convertkit.com',
  'static.cloudflareinsights.com', 'cloudflareinsights.com',

  // =====================================================
  //  EDUCATION TRACKERS
  // =====================================================
  'analytics.coursera.org', 'pixel.udemy.com',
  'analytics.edx.org', 'pixel.skillbox.ru',
  'analytics.geekbrains.ru', 'pixel.netology.ru',

  // =====================================================
  //  EMAIL TRACKING PIXELS
  // =====================================================
  'pixel.mailchimp.com', 'open.convertkit.com',
  'track.sendgrid.net', 'email.mailgun.net',
  'pixel.sendinblue.com', 'trk.klclick.com',
  'links.m.cronycle.com', 'mandrillapp.com',
];


function calcGrade(count) {
  if (count >= 6) return 'A';
  if (count >= 4) return 'B';
  if (count >= 2) return 'C';
  if (count >= 1) return 'D';
  return 'F';
}

function getDomain(url) {
  try { return new URL(url).hostname; } catch { return ''; }
}

function getBaseDomain(hostname) {
  const parts = hostname.split('.');
  return parts.slice(-2).join('.');
}

// Messages from the popup and other extension pages (content scripts run
// inside sites and must not reach these actions).
function isExtensionPage(sender) {
  return sender.id === chrome.runtime.id && String(sender.url).startsWith(chrome.runtime.getURL(''));
}

// --- storage.session updates ---
// Read-modify-write of one key is serialized: concurrent get/set pairs used to
// overwrite each other (a burst of 30 events kept only 1).
const _sessionQueues = {};
function updateSession(key, fn) {
  const run = async () => {
    const data = await chrome.storage.session.get(key);
    const next = fn(data[key]);
    if (next !== undefined) await chrome.storage.session.set({ [key]: next });
  };
  const result = (_sessionQueues[key] || Promise.resolve()).then(run, run);
  _sessionQueues[key] = result.catch(() => {});
  return result;
}

// Update the entry of one tab in a { [tabId]: value } map.
function updateTabData(key, tabId, fn) {
  return updateSession(key, (all) => {
    all = all || {};
    const next = fn(all[tabId]);
    if (next === undefined) delete all[tabId]; else all[tabId] = next;
    return all;
  });
}

const PER_TAB_KEYS = ['trackerCounts', 'shieldEvents', 'exfilAlerts', 'auditResults', 'quantumResults'];
function clearTabData(tabId, keys) {
  delete _trackerBatch[tabId];
  return Promise.all(keys.map((key) => updateTabData(key, tabId, () => undefined)));
}

// Adds value to a capped session list; resolves true only the first time.
async function markOnce(key, value, cap = 500) {
  let added = false;
  await updateSession(key, (list) => {
    list = list || [];
    if (list.includes(value)) return undefined;
    added = true;
    list.push(value);
    return list.length > cap ? list.slice(-cap) : list;
  });
  return added;
}

// --- Notifications ---
// At most one per (tab, kind) every 30 s; texts are fixed strings plus values
// the extension itself determined — never text supplied by a page.
const NOTIFY_INTERVAL_MS = 30000;
const _lastNotified = new Map();
function showNotification(kind, tabId, title, message) {
  const key = `${tabId}|${kind}`;
  const now = Date.now();
  if (now - (_lastNotified.get(key) || 0) < NOTIFY_INTERVAL_MS) return;
  _lastNotified.set(key, now);
  chrome.notifications.create(`tg-${kind}-${now}`, { type: 'basic', iconUrl: 'icon128.png', title, message }, () => {
    void chrome.runtime.lastError;
  });
}

// --- Event payloads from content scripts ---
// Only known fields of primitive type are kept, strings are capped, so a page
// that triggers events can't bloat storage or smuggle markup into the popup.
const MAX_STR = 200;
const EVENT_FIELDS = {
  exfilAlert: ['method', 'url', 'where', 'blocked', 'timestamp'],
  fingerprintDetected: ['method', 'count', 'timestamp'],
  formBlocked: ['action', 'fields', 'timestamp'],
  minerBlocked: ['url', 'timestamp'],
  webrtcBlocked: ['timestamp'],
  keyloggerDetected: ['keyCount', 'inputCount', 'perElementCount', 'event', 'timestamp'],
  clipboardSwapBlocked: ['cryptoType', 'original', 'swapped', 'blocked', 'timestamp'],
  tabNappingBlocked: ['blockedUrl', 'timestamp'],
  jsUrlBlocked: ['url', 'count', 'timestamp'],
  dataIframeBlocked: ['src', 'count', 'timestamp'],
  cookieBannerHidden: ['count', 'timestamp'],
  jsThreatFound: ['externalThreats', 'noSRI', 'suspiciousScripts', 'obfuscatedInline', 'threats', 'timestamp'],
  darkPatternFound: ['count', 'patterns', 'timestamp'],
};
const CRYPTO_TYPES = new Set(['BTC', 'ETH', 'TRX', 'SOL', 'LTC', 'IBAN']);

function cleanPrimitive(v) {
  if (typeof v === 'string') return v.substring(0, MAX_STR);
  if (typeof v === 'number') return Number.isFinite(v) ? v : undefined;
  if (typeof v === 'boolean') return v;
  return undefined;
}

// Arrays: up to 10 primitives or flat objects of primitives (e.g. threats, patterns).
function cleanValue(v) {
  if (!Array.isArray(v)) return cleanPrimitive(v);
  return v.slice(0, 10).map((item) => {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) return cleanPrimitive(item);
    const flat = {};
    for (const [k, x] of Object.entries(item).slice(0, 8)) {
      const c = cleanPrimitive(x);
      if (c !== undefined) flat[k.substring(0, 40)] = c;
    }
    return flat;
  }).filter((x) => x !== undefined);
}

function sanitizeDetail(action, message) {
  const src = message.detail && typeof message.detail === 'object' ? message.detail : message;
  const out = {};
  for (const field of EVENT_FIELDS[action] || ['timestamp']) {
    const v = cleanValue(src[field]);
    if (v !== undefined) out[field] = v;
  }
  if (action === 'clipboardSwapBlocked' && !CRYPTO_TYPES.has(out.cryptoType)) out.cryptoType = 'crypto';
  if (typeof out.timestamp !== 'number') out.timestamp = Date.now();
  return out;
}

// --- Security Headers ---
// Extra headers to capture for audit
const AUDIT_HEADERS = [
  'access-control-allow-origin', 'access-control-allow-credentials',
  'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'
];

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== 'main_frame') return;
    if (details.tabId < 0) return;
    const headers = {};
    const foundSet = new Set(); // a header sent twice still counts once
    const auditHeaders = {};
    for (const h of details.responseHeaders || []) {
      const name = h.name.toLowerCase();
      if (SECURITY_HEADERS.includes(name)) { foundSet.add(name); headers[name] = h.value; }
      if (AUDIT_HEADERS.includes(name)) { auditHeaders[name] = h.value; }
    }
    const found = [...foundSet];
    const grade = calcGrade(found.length);
    const result = { headers, found, missing: SECURITY_HEADERS.filter(h => !foundSet.has(h)), grade, auditHeaders };
    updateTabData('headerResults', details.tabId, () => result);
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

// --- Tracker counter & blocker (batched to avoid storage thrashing) ---
const _trackerBatch = {};
let _trackerFlushTimer = null;

const TRACKER_HOSTS = new Set(TRACKER_DOMAINS.filter((d) => !d.includes('/')));
const TRACKER_PATHS = TRACKER_DOMAINS.filter((d) => d.includes('/')).map((d) => {
  const i = d.indexOf('/');
  return { host: d.slice(0, i), path: d.slice(i) };
});

function hostMatches(hostname, domain) {
  return hostname === domain || hostname.endsWith('.' + domain);
}

// Same matching as the blocking rules (||entry^): the host or a parent domain
// is listed, or a path entry matches up to a separator.
function isTrackerUrl(url) {
  for (let h = url.hostname; ; h = h.slice(h.indexOf('.') + 1)) {
    if (TRACKER_HOSTS.has(h)) return true;
    if (!h.includes('.')) break;
  }
  return TRACKER_PATHS.some(({ host, path }) => hostMatches(url.hostname, host)
    && url.pathname.startsWith(path) && /^(?:$|[^\w.%-])/.test(url.pathname.slice(path.length)));
}

function flushTrackerCounts() {
  _trackerFlushTimer = null;
  const batch = { ..._trackerBatch };
  for (const k of Object.keys(_trackerBatch)) delete _trackerBatch[k];
  for (const [tabId, updates] of Object.entries(batch)) {
    updateTabData('trackerCounts', tabId, (counts) => {
      counts = counts || { total: 0, domains: {} };
      counts.total += updates.total;
      for (const [dom, cnt] of Object.entries(updates.domains)) {
        counts.domains[dom] = (counts.domains[dom] || 0) + cnt;
      }
      return counts;
    });
  }
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    if (details.type === 'main_frame') {
      // New site page in this tab: drop what was collected for the previous one.
      // Our own warning.html keeps the phishing event it is about.
      if (/^https?:/.test(details.url)) clearTabData(details.tabId, PER_TAB_KEYS);
      return;
    }
    let url;
    try { url = new URL(details.url); } catch { return; }
    if (!isTrackerUrl(url)) return;
    // Rules only block third-party loads; count the same way
    let initiatorHost = '';
    try { initiatorHost = new URL(details.initiator).hostname; } catch {}
    if (initiatorHost && getBaseDomain(initiatorHost) === getBaseDomain(url.hostname)) return;

    const tid = details.tabId;
    if (!_trackerBatch[tid]) _trackerBatch[tid] = { total: 0, domains: {} };
    _trackerBatch[tid].total++;
    const base = getBaseDomain(url.hostname);
    _trackerBatch[tid].domains[base] = (_trackerBatch[tid].domains[base] || 0) + 1;

    // Flush every 2 seconds instead of on every request
    if (!_trackerFlushTimer) {
      _trackerFlushTimer = setTimeout(flushTrackerCounts, 2000);
    }
  },
  { urls: ['<all_urls>'] }
);

// --- Tracker blocking via declarativeNetRequest ---
const TRACKER_RESOURCE_TYPES = ['script', 'image', 'xmlhttprequest', 'sub_frame', 'ping', 'other'];

function buildTrackerRules() {
  return TRACKER_DOMAINS.map((entry, i) => ({
    id: i + 1,
    priority: 1,
    action: { type: 'block' },
    condition: {
      // `^` ends the match at a separator: ||t.co^ is t.co and its subdomains, not t.com
      urlFilter: `||${entry}^`,
      domainType: 'thirdParty',
      resourceTypes: TRACKER_RESOURCE_TYPES
    }
  }));
}

// Updates run one after another and each one applies the current setting,
// so a quick off→on ends with rules on (the old pending flag dropped the 2nd call).
let _trackerRulesQueue = Promise.resolve();
function syncTrackerRules() {
  _trackerRulesQueue = _trackerRulesQueue.then(async () => {
    const { blockTrackers } = await chrome.storage.local.get({ blockTrackers: DEFAULT_SETTINGS.blockTrackers });
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existing.map((r) => r.id),
      addRules: blockTrackers ? buildTrackerRules() : []
    });
  }).catch((e) => console.error('[Bastion] tracker rules update failed:', e));
  return _trackerRulesQueue;
}

// Settings whose default changed in that version. The pre-2.3 migration
// rewrote every key to its default on each update, so stored values of these
// keys reflect the old default rather than a user choice.
const DEFAULT_CHANGES = { '2.3': ['autoDeleteExpired', 'blockJavascriptUrls'] };

function versionLess(a, b) {
  const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) < (pb[i] || 0);
  }
  return false;
}

// Fill in missing settings without touching the user's choices.
async function migrateSettings({ reason, previousVersion }) {
  const stored = await chrome.storage.local.get(null);
  const patch = { _version: chrome.runtime.getManifest().version };
  for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
    if (!(key in stored)) patch[key] = value;
  }
  if (reason === 'update' && previousVersion) {
    for (const [version, keys] of Object.entries(DEFAULT_CHANGES)) {
      if (versionLess(previousVersion, version)) {
        for (const key of keys) patch[key] = DEFAULT_SETTINGS[key];
      }
    }
  }
  await chrome.storage.local.set(patch);
}
chrome.runtime.onInstalled.addListener(migrateSettings);

// Dynamic rules persist across restarts; rebuild them on install/update,
// browser start and when the setting changes — not on every worker wake-up.
chrome.runtime.onInstalled.addListener(() => { syncTrackerRules(); });
chrome.runtime.onStartup.addListener(() => { syncTrackerRules(); });
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.blockTrackers) syncTrackerRules();
});

// --- TLS info ---
// Chrome does not expose the negotiated key exchange or cipher to extensions
// (webRequest.getSecurityInfo exists only in Firefox), so the post-quantum
// status of an HTTPS page is 'unknown' — never guessed from other data.
function initialTlsInfo(url) {
  const isHttps = url.startsWith('https://');
  return {
    url,
    isHttps,
    protocol: isHttps ? 'TLS' : (url.startsWith('http://') ? 'HTTP' : 'other'),
    pqStatus: isHttps ? 'unknown' : 'no_tls', // unknown | no_tls
    keyExchange: null,
    cipher: null,
    timestamp: Date.now()
  };
}

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.type !== 'main_frame' || details.tabId < 0) return;
    updateTabData('quantumResults', details.tabId, () => initialTlsInfo(details.url || ''));
  },
  { urls: ['<all_urls>'] }
);

// The popup can add the HTTP protocol it read from the Navigation Timing API
// (h2, h3, http/1.1). Nothing else from the report is trusted or stored.
async function checkQuantumStatus(tabId, securityInfo) {
  let tabUrl = '';
  try { tabUrl = (await chrome.tabs.get(tabId)).url || ''; } catch {}
  const protocol = securityInfo && typeof securityInfo.protocol === 'string'
    ? securityInfo.protocol.substring(0, 40) : null;
  await updateTabData('quantumResults', tabId, (info) => {
    // tabs opened before install, or pages webRequest doesn't see, have no entry yet
    info = info || initialTlsInfo(tabUrl);
    if (protocol) info.protocol = protocol;
    return info;
  });
}

// --- Messages ---
// Popup/extension-page requests. Each returns true when it answers async.
function handlePageMessage(message, sender, sendResponse) {
  const tabData = (key, fallback) => {
    chrome.storage.session.get(key, (d) => { sendResponse((d[key] || {})[message.tabId] || fallback); });
    return true;
  };
  switch (message.action) {
    case 'getHeaderResults': return tabData('headerResults', null);
    case 'getExfilAlerts': return tabData('exfilAlerts', []);
    case 'getTrackerCount': return tabData('trackerCounts', { total: 0, domains: {} });
    case 'getShieldEvents': return tabData('shieldEvents', []);
    case 'getQuantumStatus': return tabData('quantumResults', null);
    case 'getAuditResults': return tabData('auditResults', null);
    case 'getHistory':
      chrome.storage.local.get('history', (d) => { sendResponse(d.history || []); });
      return true;
    case 'getSettings':
      chrome.storage.local.get(DEFAULT_SETTINGS, (s) => { sendResponse(s); });
      return true;
    case 'getAutoDeleteLog':
      chrome.storage.session.get('autoDeleteLog', (d) => { sendResponse(d.autoDeleteLog || []); });
      return true;
    case 'setSettings':
      // content scripts pick changes up via chrome.storage.onChanged
      chrome.storage.local.set(cleanSettings(message.settings), () => { sendResponse({ ok: true }); });
      return true;
    case 'startActiveAll':
      runActiveAudit(message, sender).then(sendResponse, (e) => sendResponse({ error: e.message }));
      return true;
    case 'reportSecurityInfo':
      checkQuantumStatus(message.tabId, message.securityInfo).then(() => sendResponse({ ok: true }));
      return true;
  }
  return false;
}

// Only known settings with boolean values are written.
function cleanSettings(settings) {
  const out = {};
  if (!settings || typeof settings !== 'object') return out;
  for (const key of Object.keys(DEFAULT_SETTINGS)) {
    if (typeof settings[key] === 'boolean') out[key] = settings[key];
  }
  return out;
}

const SHIELD_EVENT_ACTIONS = new Set([
  'fingerprintDetected', 'formBlocked', 'minerBlocked', 'cookieBannerHidden', 'webrtcBlocked',
  'keyloggerDetected', 'tabNappingBlocked', 'jsUrlBlocked', 'dataIframeBlocked',
  'clipboardSwapBlocked', 'jsThreatFound', 'darkPatternFound',
]);

// Content-script reports. None of them answers, so the channel is not kept open.
function handleContentMessage(message, sender) {
  const tabId = sender.tab.id;
  const action = message.action;
  if (action === 'autoScanResult') {
    handleAutoScan(message, sender);
  } else if (action === 'exfilAlert') {
    handleExfilAlert(sanitizeDetail('exfilAlert', message), tabId);
  } else if (action === 'autoDeletedExpired') {
    handleAutoDeleted(message, sender);
  } else if (action === 'breachCheckRequest') {
    handleBreachCheck(message.passwords, tabId);
  } else if (action === 'phishingDetected') {
    handlePhishingDetected(message, sender);
  } else if (SHIELD_EVENT_ACTIONS.has(action)) {
    addShieldEvent(tabId, { action, detail: sanitizeDetail(action, message) });
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !message || typeof message.action !== 'string') return false;
  if (isExtensionPage(sender)) return handlePageMessage(message, sender, sendResponse);
  if (sender.tab) handleContentMessage(message, sender);
  return false;
});

function addShieldEvent(tabId, event) {
  const write = updateTabData('shieldEvents', tabId, (events) => {
    events = events || [];
    events.push({ action: event.action, detail: event.detail, timestamp: Date.now() });
    return events.length > 50 ? events.slice(-50) : events;
  });

  // Notifications for critical events (fixed texts, rate-limited per tab)
  if (event.action === 'clipboardSwapBlocked') {
    showNotification(event.action, tabId, 'Bastion: Clipboard Swap BLOCKED!',
      `A script tried to replace your ${event.detail.cryptoType} address in clipboard! Original address restored.`);
  } else if (event.action === 'minerBlocked') {
    showNotification(event.action, tabId, 'Bastion', 'Crypto miner blocked on this page!');
  }
  return write;
}

// --- Anti-phishing interstitial ---
// content.js reports a lookalike domain; the tab is sent to warning.html, an
// extension page the site can't remove or restyle. "Continue" there adds the
// domain to phishingAllowlist.
const PHISHING_BRANDS = ['Google', 'Apple', 'Microsoft', 'Facebook', 'Amazon', 'PayPal', 'Netflix',
  'Twitter/X', 'Telegram', 'Sberbank', 'Tinkoff/T-Bank', 'VTB', 'Alfa-Bank', 'WhatsApp', 'Binance', 'Homograph'];

// A listed brand, optionally with the " (IDN)" suffix content.js adds for
// punycode lookalikes (kept, so warning.html can say so); anything else is 'Unknown'.
function phishingBrand(name) {
  name = String(name || '');
  const base = name.endsWith(' (IDN)') ? name.slice(0, -' (IDN)'.length) : name;
  return PHISHING_BRANDS.includes(base) ? name : 'Unknown';
}

async function handlePhishingDetected(message, sender) {
  if (!sender.tab || sender.frameId !== 0) return;
  let url;
  try { url = new URL(sender.url); } catch { return; }
  if (!/^https?:$/.test(url.protocol)) return;
  const domain = url.hostname;
  const brand = phishingBrand(message.brand);
  const { phishingAllowlist = [] } = await chrome.storage.local.get('phishingAllowlist');
  if (phishingAllowlist.includes(domain)) return;

  await addShieldEvent(sender.tab.id, { action: 'phishingDetected', detail: { brand, domain, timestamp: Date.now() } });
  if (await markOnce('phishNotified', domain)) {
    showNotification('phishing', sender.tab.id, 'Bastion: Phishing!',
      `${domain} looks like ${brand}! Do NOT enter your password.`);
  }
  const params = new URLSearchParams({ url: url.href, domain, brand });
  await chrome.tabs.update(sender.tab.id, { url: chrome.runtime.getURL('warning.html') + '?' + params });
}

// --- Breach Check via HIBP Passwords API (free, k-anonymity) ---
// Checks passwords found in storage against the Pwned Passwords database.
// Uses SHA-1 prefix (5 chars) — only the prefix leaves the browser, full hash stays local.
// Results are cached per session and each leaked password is reported once.
async function sha1Hex(value) {
  const hash = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function pwnedCount(hashHex) {
  const { breachCache = {} } = await chrome.storage.session.get('breachCache');
  if (hashHex in breachCache) return breachCache[hashHex];
  const resp = await fetch(`https://api.pwnedpasswords.com/range/${hashHex.substring(0, 5)}`, {
    headers: { 'Add-Padding': 'true' }
  });
  if (!resp.ok) return null;
  const suffix = hashHex.substring(5);
  let count = 0;
  for (const line of (await resp.text()).split('\n')) {
    const [hash, cnt] = line.split(':');
    if (hash.trim() === suffix) { count = parseInt(cnt, 10) || 0; break; }
  }
  await updateSession('breachCache', (cache) => ({ ...(cache || {}), [hashHex]: count }));
  return count;
}

async function handleBreachCheck(passwords, tabId) {
  if (!Array.isArray(passwords)) return;
  const results = [];
  let newLeaks = 0;
  let fetched = false;
  for (const entry of passwords.slice(0, 10)) {
    if (!entry || typeof entry.value !== 'string' || !entry.value || entry.value.length > 256) continue;
    try {
      const hashHex = await sha1Hex(entry.value);
      const cached = (await chrome.storage.session.get('breachCache')).breachCache || {};
      // Delay between network requests to respect rate limits
      if (fetched && !(hashHex in cached)) await new Promise(r => setTimeout(r, 1500));
      fetched = fetched || !(hashHex in cached);
      const exposures = await pwnedCount(hashHex);
      if (!exposures) continue;
      results.push({ key: String(entry.key || '').substring(0, MAX_STR), storage: String(entry.storage || '').substring(0, 20), exposures });
      if (await markOnce('breachNotified', hashHex)) newLeaks++;
    } catch {}
  }

  if (results.length > 0) {
    addShieldEvent(tabId, { action: 'breachFound', detail: { results, timestamp: Date.now() } });
  }
  if (newLeaks > 0) {
    showNotification('breach', tabId, 'Bastion: Leaked Password!',
      `${newLeaks} password(s) in storage found in data breaches!`);
  }
}

// --- Active SQL Injection Testing ---
const SQL_ERROR_PATTERNS = [
  // MySQL / MariaDB
  /SQL syntax.*MySQL/i, /Warning.*mysql_/i, /MySqlException/i,
  /valid MySQL result/i, /mysqli?_[\w]+\(\)/i,
  /MariaDB server version/i,
  // PostgreSQL
  /PostgreSQL.*ERROR/i, /pg_query\(\)/i, /pg_exec\(\)/i, /PSQLException/i,
  /ERROR:\s+syntax error at or near/i,
  // MSSQL
  /Microsoft.*ODBC.*SQL/i, /Unclosed quotation mark/i,
  /SqlException/i, /mssql_query\(\)/i,
  /Microsoft SQL Native Client/i,
  // Oracle
  /ORA-\d{5}/i, /Oracle.*Driver/i, /oracle\.jdbc/i,
  // SQLite
  /SQLite3?::Exception/i, /SQLITE_ERROR/i, /near ".*": syntax error/i,
  // PHP
  /PDOException/i, /SQLSTATE\[/i,
  // Java
  /java\.sql\.SQLException/i, /jdbc\..*Exception/i,
  /org\.hibernate/i, /javax\.persistence/i,
  // Python
  /psycopg2\..*Error/i, /pymysql\..*Error/i,
  /sqlite3\.OperationalError/i, /django\.db\.utils/i,
  /sqlalchemy\.exc\./i,
  // .NET
  /System\.Data\.SqlClient/i, /System\.Data\.OleDb/i,
  /Npgsql\..*Exception/i, /MySql\.Data/i,
  // Ruby
  /ActiveRecord::StatementInvalid/i, /PG::SyntaxError/i,
  /Mysql2::Error/i,
  // NoSQL (MongoDB)
  /MongoError/i, /MongoServerError/i,
  /\$where.*\$gt|\$ne.*\$where/i,
  // Generic
  /SQL error/i, /database error/i, /query error/i,
  /syntax error.*SQL/i, /unexpected end of SQL/i,
];

const SQLI_PAYLOADS = [
  // Classic string injection
  "'",
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' /*",
  // Double quotes
  '"',
  '" OR "1"="1',
  // Numeric injection (no quotes)
  "1 OR 1=1",
  "1 OR 1=1--",
  "1) OR (1=1",
  // Backtick (MySQL)
  "`",
  // UNION-based
  "' UNION SELECT NULL--",
  "' UNION SELECT 1,2,3--",
  // Comment-based
  "1'--",
  "1'/*",
  // MSSQL specific
  "' AND 1=CONVERT(int,@@version)--",
  // NoSQL (MongoDB)
  "{'$gt':''}",
  "[$ne]=1",
];

// Time-based blind SQLi payloads (measured by response delay)
const BLIND_SQLI_PAYLOADS = [
  { payload: "' OR SLEEP(3)--", db: 'MySQL' },
  { payload: "'; WAITFOR DELAY '0:0:3'--", db: 'MSSQL' },
  { payload: "' || pg_sleep(3)--", db: 'PostgreSQL' },
  { payload: "1; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--", db: 'PostgreSQL' },
];

const BLIND_DELAY_THRESHOLD = 2500; // ms — if response takes >2.5s, likely blind SQLi

// --- Command Injection Payloads (safe — only echo a marker string) ---
const CMDI_PAYLOADS = [
  // Linux/Unix — expr outputs computed result, not the payload itself
  { payload: '; expr 13579 + 24680', check: /38259/ },
  { payload: '| expr 13579 + 24680', check: /38259/ },
  { payload: '`expr 13579 + 24680`', check: /38259/ },
  { payload: '$(expr 13579 + 24680)', check: /38259/ },
  // Windows — set /a outputs computed result
  { payload: '& set /a 13579+24680', check: /38259/ },
  { payload: '| set /a 13579+24680', check: /38259/ },
];

// --- NoSQL Injection Payloads ---
const NOSQL_PAYLOADS = [
  { payload: '{"$gt":""}', check: null },  // JSON body — check for data leak (more results than expected)
  { payload: '[$ne]=1', check: null },
  { payload: "' || '1'=='1", check: null },
  { payload: '{$where: "return true"}', check: null },
  { payload: "true, $or: [ {} ]", check: null },
];
const NOSQL_ERROR_PATTERNS = [
  /MongoError/i, /MongoServerError/i, /MongoNetworkError/i,
  /BSONTypeError/i, /BSONError/i,
  /CastError.*ObjectId/i,
  /Cast to ObjectId failed/i,
  /\$where.*not allowed/i,
  /E11000 duplicate key/i,
  /invalid operator.*\$(gt|ne|or|and|regex|where)/i,
  /mongodb:\/\//i,
  /Cannot use.*\$gt/i, /unknown operator.*\$/i,
  /Unexpected token.*JSON/i,
];

// --- SSTI (Server-Side Template Injection) Payloads ---
const SSTI_PAYLOADS = [
  { payload: '{{91*37}}', check: /3367/, engine: 'Jinja2/Twig' },
  { payload: '${91*37}', check: /3367/, engine: 'Freemarker/Mako' },
  { payload: '<%= 91*37 %>', check: /3367/, engine: 'ERB/EJS' },
  { payload: '#{91*37}', check: /3367/, engine: 'Pug/Slim' },
  { payload: '{{constructor.constructor("return 91*37")()}}', check: /3367/, engine: 'AngularJS/Vue sandbox' },
  { payload: '{php}echo 91*37;{/php}', check: /3367/, engine: 'Smarty' },
];

// --- Path Traversal Payloads ---
const PATH_TRAVERSAL_PAYLOADS = [
  { payload: '../../../../etc/passwd', check: /root:.*:0:0/i },
  { payload: '..\\..\\..\\..\\windows\\win.ini', check: /\[fonts\]|\[extensions\]/i },
  { payload: '....//....//....//etc/passwd', check: /root:.*:0:0/i },
  { payload: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', check: /root:.*:0:0/i },
  { payload: '..%252f..%252f..%252fetc/passwd', check: /root:.*:0:0/i },
];

// Active tests send attack payloads, so they run only when an extension page
// asks, only against the active tab's own origin, and never submit POST forms
// (those can change data) or anything the user typed.
async function prepareActiveAudit(message, sender) {
  // Extension pages only: content scripts run inside sites and must not trigger this
  if (sender.id !== chrome.runtime.id || !String(sender.url).startsWith(chrome.runtime.getURL(''))) {
    throw new Error('forbidden');
  }
  const tab = await chrome.tabs.get(message.tabId);
  const origin = new URL(tab.url).origin;
  const page = new URL(message.url);
  if (!/^https?:$/.test(page.protocol) || page.origin !== origin) throw new Error('origin mismatch');
  const sameOrigin = (u) => { try { return new URL(u).origin === origin; } catch { return false; } };
  const forms = (Array.isArray(message.forms) ? message.forms : [])
    .filter((f) => f && f.method === 'GET' && sameOrigin(f.action))
    .map((f) => ({ ...f, inputs: (f.inputs || []).filter((i) => i && i.name && i.type !== 'password') }))
    .filter((f) => f.inputs.length > 0);
  const params = (Array.isArray(message.params) ? message.params : [])
    .filter((p) => p && typeof p.key === 'string')
    .map((p) => ({ key: p.key, value: String(p.value ?? '') }));
  return { url: page.href, params, forms, tabId: tab.id };
}

async function runActiveAudit(message, sender) {
  const { url, params, forms, tabId } = await prepareActiveAudit(message, sender);
  // One suite at a time: parallel suites against the same host skew the
  // time-based checks and multiply the load on the site.
  const sqli = await runActiveSqliTest(url, params, tabId);
  const xss = await runActiveXssTest(url, params, tabId);
  const nosql = await runActiveNoSqlTest(url, params, tabId);
  const ssti = await runActiveSstiTest(url, params, tabId);
  const path = await runActivePathTest(url, params, tabId);
  const cmdi = await runActiveCmdInjTest(url, params, tabId);
  const formResults = await runActiveFormTest(url, forms, tabId);
  return { sqli: [...sqli, ...nosql], xss, formResults: [...formResults, ...ssti, ...path, ...cmdi] };
}

// Response of the untouched page; a signature that is already there is not evidence.
async function fetchBaselineText(pageUrl) {
  try {
    const resp = await fetch(pageUrl, {
      method: 'GET', credentials: 'omit', redirect: 'follow', signal: AbortSignal.timeout(5000)
    });
    return (await resp.text()).substring(0, 50000);
  } catch { return ''; }
}

async function runActiveSqliTest(pageUrl, params, tabId) {
  const results = [];
  if (!params || params.length === 0) return results;
  const baseText = await fetchBaselineText(pageUrl);

  // Phase 1: Error-based testing
  for (const param of params.slice(0, 5)) {
    let found = false;
    for (const payload of SQLI_PAYLOADS) {
      if (found) break;
      try {
        const url = new URL(pageUrl);
        url.searchParams.set(param.key, param.value + payload);
        const resp = await fetch(url.href, {
          method: 'GET',
          credentials: 'omit',
          redirect: 'follow',
          signal: AbortSignal.timeout(5000)
        });
        const text = await resp.text();
        const textSlice = text.substring(0, 50000);
        for (const pattern of SQL_ERROR_PATTERNS) {
          if (pattern.test(textSlice) && !pattern.test(baseText)) {
            results.push({
              type: 'sqli', subtype: 'active_error', severity: 'critical',
              param: param.key, payload: payload,
              detail: `SQL error triggered by injecting into "${param.key}"`
            });
            found = true;
            break;
          }
        }
      } catch {}
    }
    if (params.length > 1) await new Promise(r => setTimeout(r, 200));
  }

  // Phase 2: Time-based blind testing (only for params not already flagged)
  const flaggedParams = new Set(results.map(r => r.param));
  for (const param of params.slice(0, 3)) {
    if (flaggedParams.has(param.key)) continue;

    // First, measure baseline response time
    let baseline = 0;
    try {
      const url = new URL(pageUrl);
      const t0 = Date.now();
      await fetch(url.href, { method: 'GET', credentials: 'omit', signal: AbortSignal.timeout(5000) });
      baseline = Date.now() - t0;
    } catch { continue; }

    for (const bp of BLIND_SQLI_PAYLOADS) {
      try {
        const url = new URL(pageUrl);
        url.searchParams.set(param.key, param.value + bp.payload);
        const t0 = Date.now();
        await fetch(url.href, {
          method: 'GET',
          credentials: 'omit',
          redirect: 'follow',
          signal: AbortSignal.timeout(8000)
        });
        const elapsed = Date.now() - t0;

        if (elapsed - baseline > BLIND_DELAY_THRESHOLD) {
          results.push({
            type: 'sqli', subtype: 'active_blind', severity: 'critical',
            param: param.key, payload: bp.payload,
            detail: `Blind SQLi (${bp.db}): "${param.key}" — response delayed by ${Math.round((elapsed - baseline) / 1000)}s`
          });
          break;
        }
      } catch {}
    }
    await new Promise(r => setTimeout(r, 300));
  }

  // Store results
  updateTabData('auditResults', tabId, (ar) => ({ passive: [], ...ar, active: results }));

  return results;
}

// --- Active XSS Testing ---
// Injects payloads into URL params and checks if they appear unescaped in response
const XSS_PAYLOADS = [
  { payload: '<bastion_xss_test>', check: /<bastion_xss_test>/ },
  { payload: '"><img src=x onerror=bastion_xss>', check: /onerror=bastion_xss/ },
  { payload: "'-alert('bastion')-'", check: /alert\('bastion'\)/ },
  { payload: '<svg/onload=bastion_xss>', check: /<svg\/onload=bastion_xss>/ },
  { payload: 'javascript:bastion_xss', check: /javascript:bastion_xss/ },
];

async function runActiveXssTest(pageUrl, params, tabId) {
  const results = [];
  if (!params || params.length === 0) return results;

  for (const param of params.slice(0, 5)) {
    for (const xss of XSS_PAYLOADS) {
      try {
        const url = new URL(pageUrl);
        url.searchParams.set(param.key, xss.payload);
        const resp = await fetch(url.href, {
          method: 'GET',
          credentials: 'omit',
          redirect: 'follow',
          signal: AbortSignal.timeout(5000)
        });
        const text = await resp.text();
        const textSlice = text.substring(0, 50000);
        if (xss.check.test(textSlice)) {
          results.push({
            type: 'xss', subtype: 'active_reflected', severity: 'critical',
            param: param.key, payload: xss.payload,
            detail: `XSS payload reflected unescaped in "${param.key}"`
          });
          break;
        }
      } catch {}
    }
    if (params.length > 1) await new Promise(r => setTimeout(r, 300));
  }

  // Store results
  updateTabData('auditResults', tabId, (ar) => ({ passive: [], active: [], ...ar, activeXss: results }));

  return results;
}

// --- Active Command Injection Testing ---
async function runActiveCmdInjTest(pageUrl, params, tabId) {
  const results = [];
  if (!params || params.length === 0) return results;

  // Baseline: check if 38259 already exists on the page
  let baselineHasMarker = false;
  try {
    const baseUrl = new URL(pageUrl);
    baseUrl.searchParams.set(params[0].key, 'bastion_baseline_test');
    const baseResp = await fetch(baseUrl.href, {
      method: 'GET', credentials: 'omit',
      redirect: 'follow', signal: AbortSignal.timeout(5000)
    });
    const baseText = (await baseResp.text()).substring(0, 50000);
    baselineHasMarker = /38259/.test(baseText);
  } catch {}

  if (baselineHasMarker) return results; // marker already on page, can't test reliably

  for (const param of params.slice(0, 5)) {
    let found = false;
    for (const cmd of CMDI_PAYLOADS) {
      if (found) break;
      try {
        const url = new URL(pageUrl);
        url.searchParams.set(param.key, param.value + cmd.payload);
        const resp = await fetch(url.href, {
          method: 'GET', credentials: 'omit',
          redirect: 'follow', signal: AbortSignal.timeout(5000)
        });
        const text = (await resp.text()).substring(0, 50000);
        if (cmd.check.test(text)) {
          results.push({
            type: 'cmdi', subtype: 'active_cmdi', severity: 'critical',
            param: param.key, payload: cmd.payload,
            detail: `Command Injection: OS command executed via "${param.key}"`
          });
          found = true;
        }
      } catch {}
    }
    await new Promise(r => setTimeout(r, 200));
  }
  return results;
}

// --- Active NoSQL Injection Testing ---
async function runActiveNoSqlTest(pageUrl, params, tabId) {
  const results = [];
  if (!params || params.length === 0) return results;

  // Baseline: fetch the page with a normal value to detect existing error patterns
  const baselinePatterns = new Set();
  try {
    const baseUrl = new URL(pageUrl);
    baseUrl.searchParams.set(params[0].key, 'bastion_baseline_test');
    const baseResp = await fetch(baseUrl.href, {
      method: 'GET', credentials: 'omit',
      redirect: 'follow', signal: AbortSignal.timeout(5000)
    });
    const baseText = (await baseResp.text()).substring(0, 50000);
    for (const pattern of NOSQL_ERROR_PATTERNS) {
      if (pattern.test(baseText)) baselinePatterns.add(pattern.source);
    }
  } catch {}

  for (const param of params.slice(0, 5)) {
    for (const nosql of NOSQL_PAYLOADS) {
      try {
        const url = new URL(pageUrl);
        url.searchParams.set(param.key, nosql.payload);
        const resp = await fetch(url.href, {
          method: 'GET', credentials: 'omit',
          redirect: 'follow', signal: AbortSignal.timeout(5000)
        });
        const text = (await resp.text()).substring(0, 50000);
        for (const pattern of NOSQL_ERROR_PATTERNS) {
          if (pattern.test(text) && !baselinePatterns.has(pattern.source)) {
            results.push({
              type: 'sqli', subtype: 'active_nosql', severity: 'critical',
              param: param.key, payload: nosql.payload,
              detail: `NoSQL injection error in "${param.key}"`
            });
            break;
          }
        }
      } catch {}
    }
    await new Promise(r => setTimeout(r, 200));
  }
  return results;
}

// --- Active SSTI Testing ---
async function runActiveSstiTest(pageUrl, params, tabId) {
  const results = [];
  if (!params || params.length === 0) return results;

  // Baseline: fetch the page with a harmless value to get the normal response
  let baselineText = '';
  try {
    const baseUrl = new URL(pageUrl);
    baseUrl.searchParams.set(params[0].key, 'bastion_baseline_test');
    const baseResp = await fetch(baseUrl.href, {
      method: 'GET', credentials: 'omit',
      redirect: 'follow', signal: AbortSignal.timeout(5000)
    });
    baselineText = (await baseResp.text()).substring(0, 50000);
  } catch {}

  for (const param of params.slice(0, 5)) {
    let found = false;
    for (const ssti of SSTI_PAYLOADS) {
      if (found) break;
      try {
        const url = new URL(pageUrl);
        url.searchParams.set(param.key, ssti.payload);
        const resp = await fetch(url.href, {
          method: 'GET', credentials: 'omit',
          redirect: 'follow', signal: AbortSignal.timeout(5000)
        });
        const text = (await resp.text()).substring(0, 50000);
        // Check if the template was executed (e.g. 7*7 = 49)
        // But filter out: payload reflected literally, or result already present in baseline
        if (ssti.check.test(text) && !text.includes(ssti.payload) && !ssti.check.test(baselineText)) {
          results.push({
            type: 'ssti', subtype: 'active_ssti', severity: 'critical',
            param: param.key, payload: ssti.payload,
            detail: `SSTI (${ssti.engine}): template executed in "${param.key}"`
          });
          found = true;
        }
      } catch {}
    }
    await new Promise(r => setTimeout(r, 200));
  }
  return results;
}

// --- Active Path Traversal Testing ---
async function runActivePathTest(pageUrl, params, tabId) {
  const results = [];
  if (!params || params.length === 0) return results;
  const baseText = await fetchBaselineText(pageUrl);

  for (const param of params.slice(0, 5)) {
    let found = false;
    for (const pt of PATH_TRAVERSAL_PAYLOADS) {
      if (found) break;
      try {
        const url = new URL(pageUrl);
        url.searchParams.set(param.key, pt.payload);
        const resp = await fetch(url.href, {
          method: 'GET', credentials: 'omit',
          redirect: 'follow', signal: AbortSignal.timeout(5000)
        });
        const text = (await resp.text()).substring(0, 50000);
        if (pt.check.test(text) && !pt.check.test(baseText)) {
          results.push({
            type: 'path_traversal', subtype: 'active_path', severity: 'critical',
            param: param.key, payload: pt.payload,
            detail: `Path Traversal: file content leaked via "${param.key}"`
          });
          found = true;
        }
      } catch {}
    }
    await new Promise(r => setTimeout(r, 200));
  }
  return results;
}

// --- Active Form Testing ---
// Tests form inputs for SQLi and XSS by submitting payloads
const FORM_SQLI_PAYLOADS = ["'", "' OR '1'='1", "1' OR '1'='1'--", "\" OR \"1\"=\"1", "1; DROP TABLE--"];
const FORM_XSS_PAYLOADS = [
  { payload: '<bastion_xss_form>', check: /<bastion_xss_form>/ },
  { payload: '"><img src=x onerror=bastion_form>', check: /onerror=bastion_form/ },
];
const FORM_SSTI_PAYLOADS = [
  { payload: '{{91*37}}', check: /3367/, engine: 'Jinja2/Twig' },
  { payload: '${91*37}', check: /3367/, engine: 'Freemarker/Mako' },
];
const FORM_NOSQL_PAYLOADS = ['{"$gt":""}', "' || '1'=='1"];
const FORM_PATH_PAYLOADS = [
  { payload: '../../../../etc/passwd', check: /root:.*:0:0/i },
];
const FORM_CMDI_PAYLOADS = [
  { payload: '; expr 13579 + 24680', check: /38259/ },
  { payload: '| expr 13579 + 24680', check: /38259/ },
];

async function runActiveFormTest(pageUrl, forms, tabId) {
  const results = [];
  if (!forms || forms.length === 0) return results;

  // Test max 3 forms, max 3 inputs per form
  for (const form of forms.slice(0, 3)) {
    const testInputs = form.inputs.slice(0, 3);

    // Baseline for form — send normal value to get base response
    let formBaselineText = '';
    const formBaselineNoSqlPatterns = new Set();
    if (testInputs.length > 0) {
      try {
        formBaselineText = await sendFormPayload(form, testInputs[0].name, 'bastion_baseline');
      } catch {}
      for (const pattern of NOSQL_ERROR_PATTERNS) {
        if (pattern.test(formBaselineText)) formBaselineNoSqlPatterns.add(pattern.source);
      }
    }


    // SQLi test
    for (const input of testInputs) {
      let found = false;
      for (const payload of FORM_SQLI_PAYLOADS) {
        if (found) break;
        try {
          const text = await sendFormPayload(form, input.name, payload);
          for (const pattern of SQL_ERROR_PATTERNS) {
            if (pattern.test(text) && !pattern.test(formBaselineText)) {
              results.push({
                type: 'sqli', subtype: 'active_form_error', severity: 'critical',
                param: input.name, payload,
                detail: `SQL error in form field "${input.name}" (${form.method})`
              });
              found = true;
              break;
            }
          }
        } catch {}
      }
      await new Promise(r => setTimeout(r, 200));
    }

    // XSS test
    for (const input of testInputs) {
      for (const xss of FORM_XSS_PAYLOADS) {
        try {
          const text = await sendFormPayload(form, input.name, xss.payload);
          if (xss.check.test(text)) {
            results.push({
              type: 'xss', subtype: 'active_form_reflected', severity: 'critical',
              param: input.name, payload: xss.payload,
              detail: `XSS reflected in form field "${input.name}" (${form.method})`
            });
            break;
          }
        } catch {}
      }
      await new Promise(r => setTimeout(r, 200));
    }

    // SSTI test
    for (const input of testInputs) {
      for (const ssti of FORM_SSTI_PAYLOADS) {
        try {
          const text = await sendFormPayload(form, input.name, ssti.payload);
          if (ssti.check.test(text) && !text.includes(ssti.payload) && !ssti.check.test(formBaselineText)) {
            results.push({
              type: 'ssti', subtype: 'active_form_ssti', severity: 'critical',
              param: input.name, payload: ssti.payload,
              detail: `SSTI (${ssti.engine}) in form field "${input.name}" (${form.method})`
            });
            break;
          }
        } catch {}
      }
      await new Promise(r => setTimeout(r, 200));
    }

    // NoSQL test
    for (const input of testInputs) {
      for (const payload of FORM_NOSQL_PAYLOADS) {
        try {
          const text = await sendFormPayload(form, input.name, payload);
          for (const pattern of NOSQL_ERROR_PATTERNS) {
            if (pattern.test(text) && !formBaselineNoSqlPatterns.has(pattern.source)) {
              results.push({
                type: 'sqli', subtype: 'active_form_nosql', severity: 'critical',
                param: input.name, payload,
                detail: `NoSQL injection in form field "${input.name}" (${form.method})`
              });
              break;
            }
          }
        } catch {}
      }
      await new Promise(r => setTimeout(r, 200));
    }

    // Path Traversal test
    for (const input of testInputs) {
      for (const pt of FORM_PATH_PAYLOADS) {
        try {
          const text = await sendFormPayload(form, input.name, pt.payload);
          if (pt.check.test(text) && !pt.check.test(formBaselineText)) {
            results.push({
              type: 'path_traversal', subtype: 'active_form_path', severity: 'critical',
              param: input.name, payload: pt.payload,
              detail: `Path Traversal in form field "${input.name}" (${form.method})`
            });
            break;
          }
        } catch {}
      }
      await new Promise(r => setTimeout(r, 200));
    }

    // Command Injection test
    for (const input of testInputs) {
      let found = false;
      for (const cmd of FORM_CMDI_PAYLOADS) {
        if (found) break;
        try {
          const text = await sendFormPayload(form, input.name, cmd.payload);
          if (cmd.check.test(text) && !cmd.check.test(formBaselineText)) {
            results.push({
              type: 'cmdi', subtype: 'active_form_cmdi', severity: 'critical',
              param: input.name, payload: cmd.payload,
              detail: `Command Injection in form field "${input.name}" (${form.method})`
            });
            found = true;
          }
        } catch {}
      }
      await new Promise(r => setTimeout(r, 200));
    }
  }

  // Deduplicate: same type + param + subtype = one finding
  const seen = new Set();
  const deduped = results.filter(r => {
    const key = `${r.type}|${r.subtype}|${r.param}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return deduped;
}

// Helper: send payload to a form field (GET forms only, see prepareActiveAudit).
// Other fields get a placeholder so nothing the user typed leaves the page.
async function sendFormPayload(form, targetField, payload) {
  if (form.method !== 'GET') throw new Error('only GET forms are tested');
  const url = new URL(form.action);
  for (const inp of form.inputs) {
    url.searchParams.set(inp.name, inp.name === targetField ? payload : 'test');
  }
  const resp = await fetch(url.href, {
    method: 'GET', credentials: 'omit', redirect: 'follow',
    signal: AbortSignal.timeout(5000)
  });
  return (await resp.text()).substring(0, 50000);
}

function handleAutoScan(message, sender) {
  const tabId = sender.tab.id;
  const findings = Array.isArray(message.findings) ? message.findings.slice(0, 500) : [];
  const url = sender.url || '';
  const count = findings.length;
  const criticalCount = findings.filter(f => f && f.severity === 'critical').length;

  chrome.storage.session.get('headerResults', (data) => {
    const hr = (data.headerResults || {})[tabId];
    const headerGrade = hr ? hr.grade : '?';
    let finalGrade;
    if (headerGrade !== '?') {
      const grades = ['A', 'B', 'C', 'D', 'F'];
      let idx = grades.indexOf(headerGrade);
      if (criticalCount >= 3) idx = Math.min(idx + 2, 4);
      else if (criticalCount >= 1) idx = Math.min(idx + 1, 4);
      finalGrade = grades[idx];
    } else if (criticalCount > 0) { finalGrade = 'F'; }
    else if (count > 0) { finalGrade = 'D'; }
    else { finalGrade = 'A'; }

    const gradeColors = { 'A': '#22c55e', 'B': '#4ade80', 'C': '#f59e0b', 'D': '#f97316', 'F': '#ef4444', '?': '#64748b' };
    chrome.action.setBadgeText({ text: finalGrade, tabId });
    chrome.action.setBadgeBackgroundColor({ color: gradeColors[finalGrade] || '#64748b', tabId });
    chrome.action.setTitle({ title: count > 0
      ? `Bastion [${finalGrade}]: ${count} findings (${criticalCount} critical)`
      : `Bastion [${finalGrade}]: safe`, tabId });
  });

  const domain = getDomain(url);
  if (criticalCount > 0 && domain) {
    markOnce('notifiedDomains', domain).then((first) => {
      if (first) {
        showNotification('critical', tabId, 'Bastion', `${criticalCount} critical vulnerabilities found on ${domain}!`);
      }
    });
  }
  saveToHistory(url, findings, tabId);
}

function saveToHistory(url, findings, tabId) {
  const domain = getDomain(url);
  if (!domain) return;
  chrome.storage.session.get('headerResults', (sessionData) => {
    // the header grade of this tab, not whichever tab was stored last
    const hr = (sessionData.headerResults || {})[tabId];
    const grade = hr ? hr.grade : '?';
    const entry = { domain, date: new Date().toISOString().split('T')[0],
      tokens: findings.filter(f => f && f.type === 'jwt').length,
      secrets: findings.filter(f => f && f.type !== 'jwt' && f.severity !== 'info').length, grade };
    chrome.storage.local.get('history', (data) => {
      let history = data.history || [];
      const idx = history.findIndex(h => h.domain === domain && h.date === entry.date);
      if (idx >= 0) history[idx] = entry; else history.unshift(entry);
      if (history.length > 200) history = history.slice(0, 200);
      chrome.storage.local.set({ history });
    });
  });
}

function handleExfilAlert(detail, tabId) {
  // popup renders method.toUpperCase(): keep it a string
  detail.method = String(detail.method ?? '');
  return updateTabData('exfilAlerts', tabId, (alerts) => {
    alerts = alerts || [];
    alerts.push(detail);
    return alerts.length > 50 ? alerts.slice(-50) : alerts;
  });
}

const STORAGE_KINDS = new Set(['localStorage', 'sessionStorage', 'cookie']);
function handleAutoDeleted(message, sender) {
  const deleted = (Array.isArray(message.deleted) ? message.deleted : []).slice(0, 20).filter(d => d && d.key);
  if (deleted.length === 0) return;
  const domain = getDomain(sender.url || '');
  updateSession('autoDeleteLog', (log) => {
    log = log || [];
    for (const d of deleted) {
      log.push({
        key: String(d.key).substring(0, MAX_STR),
        storage: STORAGE_KINDS.has(d.storage) ? d.storage : 'unknown',
        domain, timestamp: Date.now()
      });
    }
    return log.length > 100 ? log.slice(-100) : log;
  });
  showNotification('autodel', sender.tab.id, 'Bastion', `Auto-deleted ${deleted.length} expired JWT on ${domain}`);
}

// Cleanup on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  clearTabData(tabId, ['headerResults', ...PER_TAB_KEYS]);
  for (const key of _lastNotified.keys()) {
    if (key.startsWith(tabId + '|')) _lastNotified.delete(key);
  }
});
