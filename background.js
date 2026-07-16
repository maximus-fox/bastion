/**
 * TokenGuard v2.0 — Background Service Worker
 * Badge, Security Headers, notifications, history, tracker counter, shield events
 */

const SECURITY_HEADERS = [
  'strict-transport-security', 'content-security-policy', 'x-frame-options',
  'x-content-type-options', 'x-xss-protection', 'referrer-policy'
];

// Known tracker domains (compact list)
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
  'an.facebook.com', 'ads.facebook.com', 'graph.facebook.com',
  'analytics.instagram.com', 'i.instagram.com',
  'pixel.instagram.com', 'business.facebook.com',
  'www.facebook.com/tr', 'ad.atdmt.com',

  // =====================================================
  //  TWITTER / X (Global)
  // =====================================================
  'analytics.twitter.com', 'ads-twitter.com', 'ads-api.twitter.com',
  'syndication.twitter.com', 'platform.twitter.com',
  'static.ads-twitter.com', 't.co',

  // =====================================================
  //  MICROSOFT / LINKEDIN / BING
  // =====================================================
  'clarity.ms', 'bat.bing.com', 'bat.r.msn.com',
  'ads.linkedin.com', 'snap.licdn.com', 'px.ads.linkedin.com',
  'platform.linkedin.com', 'analytics.pointdrive.linkedin.com',
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
  'log.mmstat.com', 'g.alicdn.com', 'acm.aliyun.com',
  'gm.mmstat.com', 'arms-retcode.aliyuncs.com',
  // Tencent / QQ / WeChat
  'beacon.qq.com', 'pingtas.qq.com', 'report.qq.com', 'btrace.qq.com',
  'trace.qq.com', 'pgdt.gtimg.cn', 'adservice.qq.com',
  'wx.gtimg.com', 'mp.weixin.qq.com/mp/report',
  // Sina / Weibo
  'sax.sina.com.cn', 'beacon.sina.com.cn',
  'trends.weibodata.com', 'img.t.sinajs.cn',
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
  'tr.line.me', 'scdn.line-apps.com', 'obs.line-scdn.net',
  'yads.yahoo.co.jp', 'yjtag.yahoo.co.jp', 's.yimg.jp',
  'b90.yahoo.co.jp', 'retarget.yahoo.co.jp',
  'rat.rakuten.co.jp', 'r.r10s.jp', 'grp01.id.rakuten.co.jp',
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
  'analytics.mercadolibre.com', 'http2.mlstatic.com',
  'analytics.nubank.com.br', 'pixel.pagseguro.com',
  'analytics.b2w.io', 'analytics.americanas.com',

  // =====================================================
  //  EUROPE — Zalando, Criteo, Trade Desk
  // =====================================================
  'uk-ads.openx.net', 'pixel.rubiconproject.com', 'ib.adnxs.com',
  'tag.getdrip.com', 'cdn.cookielaw.org',
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
  'cdn.userback.io', 'widget.intercom.io',
  'js.driftt.com', 'widget.drift.com',
  'static.zdassets.com', 'ekr.zdassets.com',
  'cdn.livechatinc.com', 'api.livechatinc.com',
  'snap.licdn.com', 'sentry.io', 'browser.sentry-cdn.com',
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
  'arkoselabs.com', 'funcaptcha.com', 'client-api.arkoselabs.com',
  'datadome.co', 'ct.captcha-delivery.com', 'api-js.datadome.co',
  'perimeterx.net', 'px-cdn.net', 'px-cloud.net', 'px-client.net',
  'b.cdnwidget.com', 'cdn.distil.it', 'n.cdn.distil.it',
  'device.maxmind.com', 'geoip.maxmind.com',
  'risk.clearbit.com', 'reveal.clearbit.com',
  'api.fraudlogix.com', 'riskified.com', 'beacon.riskified.com',
  'forter.com', 'verifi.forter.com',
  'castle.io', 'api.castle.io',
  'shield.sift.com', 'cdn.sift.com',

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
  'analytics.revolut.com', 'analytics.n26.com',
  'analytics.wise.com', 'pixel.monzo.com',
  'analytics.hsbc.com', 'pixel.barclays.co.uk',
  'analytics.ing.com', 'analytics.deutschebank.com',
  'analytics.bnpparibas.com', 'analytics.unicredit.it',
  'analytics.santander.com', 'analytics.bbva.com',
  'analytics.ubs.com', 'analytics.credit-suisse.com',
  // RU Banks
  'smetrics.sberbank.ru', 'analytics.tinkoff.ru',
  'tracking.vtb.ru', 'analytics.alfabank.ru',
  'click.alfabank.ru', 'pixel.gazprombank.ru',
  'analytics.raiffeisen.ru', 'pixel.open.ru',
  'mc.bankiros.ru', 'analytics.banki.ru',
  // India Banks
  'analytics.icicibank.com', 'pixel.hdfcbank.com',
  'analytics.axisbank.com', 'analytics.kotak.com',
  // Payment Systems
  't.paypal.com', 'pixel.paypal.com', 'analytics.paypal.com',
  'analytics.stripe.com', 'r.stripe.com', 'q.stripe.com',
  'pixel.square.com', 'analytics.squareup.com',
  'pixel.adyen.com', 'analytics.checkout.com',
  'analytics.braintreepayments.com', 'pixel.2checkout.com',
  'analytics.worldpay.com', 'pixel.klarna.com',
  'tracker.klarna.com', 'analytics.afterpay.com',
  'pixel.affirm.com', 'analytics.wise.com',

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
  'bat.bing.com', 'ct.shopify.com',
  'analytics.ebay.com', 'rover.ebay.com', 'vi.vipr.ebaydesc.com',
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
  'apis.google.com', 'w.soundcloud.com',
  'badge.stumbleupon.com', 'static.addtoany.com',
  'connect.ok.ru', 'share.yandex.ru',
  'telegram.org/js/telegram-widget.js',

  // =====================================================
  //  CDN-HOSTED TRACKERS & TAG MANAGERS
  // =====================================================
  'cdn.onesignal.com', 'onesignal.com',
  'cdn.pushwoosh.com', 'cp.pushwoosh.com',
  'sdk.pushwoosh.com', 'cdn.subscribers.com',
  'push.zalo.me', 'notix.io',
  'js.hs-scripts.com', 'forms.hsforms.com',
  'js.hubspot.com', 'api.hubapi.com',
  'pixel.convertkit.com', 'app.convertkit.com',
  'fast.wistia.com', 'embedwistia-a.akamaihd.net',
  'ct.captcha-delivery.com', 'challenges.cloudflare.com',
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

const DEFAULT_SETTINGS = {
  autoDeleteExpired: true, blockExfil: true,
  antiFingerprint: true, formSpy: true, antiMiner: true,
  antiPhishing: true, blockTrackers: true,
  hideCookieBanners: true, antiWebRTC: true,
  antiKeylogger: true, antiTabNapping: true,
  clipboardGuard: true,
  jsThreatScan: true, darkPatternDetect: true, breachCheck: true,
  blockJavascriptUrls: true, blockDataIframes: true
};

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

// --- Security Headers ---
// Extra headers to capture for audit
const AUDIT_HEADERS = [
  'access-control-allow-origin', 'access-control-allow-credentials',
  'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'
];

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== 'main_frame') return;
    const headers = {};
    const found = [];
    const auditHeaders = {};
    for (const h of details.responseHeaders || []) {
      const name = h.name.toLowerCase();
      if (SECURITY_HEADERS.includes(name)) { found.push(name); headers[name] = h.value; }
      if (AUDIT_HEADERS.includes(name)) { auditHeaders[name] = h.value; }
    }
    const grade = calcGrade(found.length);
    const result = { headers, found, missing: SECURITY_HEADERS.filter(h => !found.includes(h)), grade, auditHeaders };
    chrome.storage.session.get('headerResults', (data) => {
      const hr = data.headerResults || {};
      hr[details.tabId] = result;
      chrome.storage.session.set({ headerResults: hr });
    });
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

// --- Tracker counter & blocker (batched to avoid storage thrashing) ---
const _trackerBatch = {};
let _trackerFlushTimer = null;

function flushTrackerCounts() {
  _trackerFlushTimer = null;
  const batch = { ..._trackerBatch };
  // Clear batch
  for (const k of Object.keys(_trackerBatch)) delete _trackerBatch[k];
  if (Object.keys(batch).length === 0) return;

  chrome.storage.session.get('trackerCounts', (data) => {
    const counts = data.trackerCounts || {};
    for (const [tabId, updates] of Object.entries(batch)) {
      if (!counts[tabId]) counts[tabId] = { total: 0, domains: {} };
      counts[tabId].total += updates.total;
      for (const [dom, cnt] of Object.entries(updates.domains)) {
        counts[tabId].domains[dom] = (counts[tabId].domains[dom] || 0) + cnt;
      }
    }
    chrome.storage.session.set({ trackerCounts: counts });
  });
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type === 'main_frame') return;
    const hostname = getDomain(details.url);
    const isTracker = TRACKER_DOMAINS.some(t => hostname === t || hostname.endsWith('.' + t));

    if (isTracker && details.tabId > 0) {
      const tid = details.tabId;
      if (!_trackerBatch[tid]) _trackerBatch[tid] = { total: 0, domains: {} };
      _trackerBatch[tid].total++;
      const base = getBaseDomain(hostname);
      _trackerBatch[tid].domains[base] = (_trackerBatch[tid].domains[base] || 0) + 1;

      // Flush every 2 seconds instead of on every request
      if (!_trackerFlushTimer) {
        _trackerFlushTimer = setTimeout(flushTrackerCounts, 2000);
      }
    }
  },
  { urls: ['<all_urls>'] }
);

// --- Tracker blocking via declarativeNetRequest ---
let _trackerUpdatePending = false;
function updateTrackerRules(enabled) {
  if (!chrome.declarativeNetRequest) return;
  if (_trackerUpdatePending) return;
  _trackerUpdatePending = true;

  const allIds = TRACKER_DOMAINS.map((_, i) => i + 1);

  if (!enabled) {
    chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: allIds }, () => {
      _trackerUpdatePending = false;
    });
    return;
  }

  const rules = TRACKER_DOMAINS.map((domain, i) => ({
    id: i + 1,
    priority: 1,
    action: { type: 'block' },
    condition: {
      urlFilter: `||${domain}`,
      resourceTypes: ['script', 'image', 'xmlhttprequest', 'sub_frame', 'ping', 'other']
    }
  }));

  chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: allIds, addRules: rules }, () => {
    _trackerUpdatePending = false;
  });
}

// Migrate settings on version update — ensure new defaults apply
chrome.storage.local.get('_version', (data) => {
  const currentVersion = chrome.runtime.getManifest().version;
  if (data._version !== currentVersion) {
    // First run or version changed — apply new defaults for keys not yet set
    chrome.storage.local.set({ ...DEFAULT_SETTINGS, _version: currentVersion });
  }
});

// Init tracker blocking from settings
chrome.storage.local.get(DEFAULT_SETTINGS, (s) => {
  updateTrackerRules(s.blockTrackers);
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.blockTrackers) {
    updateTrackerRules(changes.blockTrackers.newValue);
  }
});

// --- Quantum-Ready TLS Detection ---
// Post-quantum cipher suites / key exchange groups
const PQ_INDICATORS = [
  'X25519MLKEM768', 'X25519Kyber768', 'X25519Kyber512',  // ML-KEM / Kyber hybrids
  'MLKEM768', 'MLKEM1024', 'Kyber768', 'Kyber512', 'Kyber1024',  // Pure ML-KEM
  'SecP256r1MLKEM768', 'P256Kyber768',  // NIST P-256 + ML-KEM hybrid
];
const PQ_PATTERN = /kyber|mlkem|crystals|dilithium|sphincs|falcon|frodo|ntru|saber|bike|hqc/i;

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.type !== 'main_frame' || details.tabId < 0) return;

    chrome.tabs.get(details.tabId, (tab) => {
      if (chrome.runtime.lastError || !tab) return;

      // Use chrome.tabs security state if available
      const url = details.url || '';
      const isHttps = url.startsWith('https://');
      const isHttp = url.startsWith('http://');

      // Store basic info, we'll enrich with SecurityState from popup
      const quantumInfo = {
        url: url,
        isHttps: isHttps,
        protocol: isHttps ? 'TLS' : (isHttp ? 'HTTP' : 'other'),
        pqStatus: 'unknown', // unknown, pq_safe, classic, no_tls
        keyExchange: null,
        cipher: null,
        timestamp: Date.now()
      };

      if (!isHttps) {
        quantumInfo.pqStatus = 'no_tls';
      }

      chrome.storage.session.get('quantumResults', (data) => {
        const qr = data.quantumResults || {};
        qr[details.tabId] = quantumInfo;
        chrome.storage.session.set({ quantumResults: qr });
      });
    });
  },
  { urls: ['<all_urls>'] }
);

// Enrich quantum info when SecurityState is available (from popup via debugger or tab info)
function checkQuantumStatus(tabId, securityInfo) {
  chrome.storage.session.get('quantumResults', (data) => {
    const qr = data.quantumResults || {};
    if (!qr[tabId]) return;

    if (securityInfo && securityInfo.keyExchange) {
      qr[tabId].keyExchange = securityInfo.keyExchange;
      qr[tabId].cipher = securityInfo.cipher || null;
      qr[tabId].protocol = securityInfo.protocol || qr[tabId].protocol;

      // Check if key exchange uses post-quantum algorithm
      const kex = securityInfo.keyExchange;
      const isPQ = PQ_INDICATORS.some(pq => kex.includes(pq)) || PQ_PATTERN.test(kex);
      qr[tabId].pqStatus = isPQ ? 'pq_safe' : 'classic';
    }

    chrome.storage.session.set({ quantumResults: qr });
  });
}

// --- Messages ---
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // From popup
  if (message.action === 'getHeaderResults') {
    chrome.storage.session.get('headerResults', (d) => { sendResponse((d.headerResults || {})[message.tabId] || null); });
    return true;
  } else if (message.action === 'getExfilAlerts') {
    chrome.storage.session.get('exfilAlerts', (d) => { sendResponse((d.exfilAlerts || {})[message.tabId] || []); });
    return true;
  } else if (message.action === 'getHistory') {
    chrome.storage.local.get('history', (d) => { sendResponse(d.history || []); });
    return true;
  } else if (message.action === 'getSettings') {
    chrome.storage.local.get(DEFAULT_SETTINGS, (s) => { sendResponse(s); });
    return true;
  } else if (message.action === 'setSettings') {
    chrome.storage.local.set(message.settings, () => {
      chrome.tabs.query({}, (tabs) => {
        for (const tab of tabs) {
          chrome.tabs.sendMessage(tab.id, { action: 'settingsUpdated', settings: message.settings }).catch(() => {});
        }
      });
      sendResponse({ ok: true });
    });
    return true;
  } else if (message.action === 'getAutoDeleteLog') {
    chrome.storage.session.get('autoDeleteLog', (d) => { sendResponse(d.autoDeleteLog || []); });
    return true;
  } else if (message.action === 'getTrackerCount') {
    chrome.storage.session.get('trackerCounts', (d) => { sendResponse((d.trackerCounts || {})[message.tabId] || { total: 0, domains: {} }); });
    return true;
  } else if (message.action === 'getShieldEvents') {
    chrome.storage.session.get('shieldEvents', (d) => { sendResponse((d.shieldEvents || {})[message.tabId] || []); });
    return true;
  } else if (message.action === 'getQuantumStatus') {
    chrome.storage.session.get('quantumResults', (d) => { sendResponse((d.quantumResults || {})[message.tabId] || null); });
    return true;
  } else if (message.action === 'getAuditResults') {
    chrome.storage.session.get('auditResults', (d) => { sendResponse((d.auditResults || {})[message.tabId] || null); });
    return true;
  } else if (message.action === 'startActiveSqli') {
    runActiveSqliTest(message.url, message.params, message.tabId).then(r => sendResponse(r));
    return true;
  } else if (message.action === 'startActiveXss') {
    runActiveXssTest(message.url, message.params, message.tabId).then(r => sendResponse(r));
    return true;
  } else if (message.action === 'startActiveAll') {
    Promise.all([
      runActiveSqliTest(message.url, message.params, message.tabId),
      runActiveXssTest(message.url, message.params, message.tabId),
      runActiveNoSqlTest(message.url, message.params, message.tabId),
      runActiveSstiTest(message.url, message.params, message.tabId),
      runActivePathTest(message.url, message.params, message.tabId),
      runActiveCmdInjTest(message.url, message.params, message.tabId),
      runActiveFormTest(message.url, message.forms || [], message.tabId)
    ]).then(([sqli, xss, nosql, ssti, path, cmdi, formResults]) => sendResponse({
      sqli: [...sqli, ...nosql],
      xss,
      formResults: [...formResults, ...ssti, ...path, ...cmdi]
    }));
    return true;
  } else if (message.action === 'reportSecurityInfo') {
    checkQuantumStatus(message.tabId, message.securityInfo);
    sendResponse({ ok: true });
    return true;
  }

  // From content script
  if (sender.tab) {
    const tabId = sender.tab.id;
    if (message.action === 'autoScanResult') {
      handleAutoScan(message, sender);
    } else if (message.action === 'exfilAlert') {
      handleExfilAlert(message.detail, tabId);
    } else if (message.action === 'autoDeletedExpired') {
      chrome.storage.session.get('autoDeleteLog', (data) => {
        let log = data.autoDeleteLog || [];
        for (const d of message.deleted) {
          log.push({ key: d.key, storage: d.storage, domain: getDomain(message.url), timestamp: Date.now() });
        }
        if (log.length > 100) log = log.slice(-100);
        chrome.storage.session.set({ autoDeleteLog: log });
      });
      chrome.notifications.create(`tg-autodel-${Date.now()}`, {
        type: 'basic', iconUrl: 'icon128.png', title: 'Bastion',
        message: `Auto-deleted ${message.deleted.length} expired JWT on ${getDomain(message.url)}`
      });
    } else if (message.action === 'clipboardSwapBlocked') {
      addShieldEvent(tabId, message);
    } else if (message.action === 'jsThreatFound' || message.action === 'darkPatternFound') {
      addShieldEvent(tabId, message);
    } else if (message.action === 'breachCheckRequest') {
      handleBreachCheck(message.passwords || [], tabId);
    } else if (message.action === 'fingerprintDetected' || message.action === 'formBlocked' || message.action === 'minerBlocked' || message.action === 'phishingDetected' || message.action === 'cookieBannerHidden' || message.action === 'webrtcBlocked' || message.action === 'keyloggerDetected' || message.action === 'tabNappingBlocked' || message.action === 'jsUrlBlocked' || message.action === 'dataIframeBlocked') {
      addShieldEvent(tabId, message);
    }
    return true; // keep port open for async operations
  }
});

function addShieldEvent(tabId, message) {
  chrome.storage.session.get('shieldEvents', (data) => {
    const events = data.shieldEvents || {};
    if (!events[tabId]) events[tabId] = [];
    events[tabId].push({ action: message.action, detail: message.detail || message, timestamp: Date.now() });
    if (events[tabId].length > 50) events[tabId] = events[tabId].slice(-50);
    chrome.storage.session.set({ shieldEvents: events });
  });

  // Уведомление для критических событий
  if (message.action === 'phishingDetected') {
    chrome.notifications.create(`tg-phish-${Date.now()}`, {
      type: 'basic', iconUrl: 'icon128.png', title: 'Bastion: Phishing!',
      message: `${message.domain || message.brand} looks like ${message.brand}! Do NOT enter your password.`
    });
  } else if (message.action === 'clipboardSwapBlocked') {
    chrome.notifications.create(`tg-clip-${Date.now()}`, {
      type: 'basic', iconUrl: 'icon128.png', title: 'Bastion: Clipboard Swap BLOCKED!',
      message: `A script tried to replace your ${message.detail?.cryptoType || 'crypto'} address in clipboard! Original address restored.`
    });
  } else if (message.action === 'minerBlocked') {
    chrome.notifications.create(`tg-miner-${Date.now()}`, {
      type: 'basic', iconUrl: 'icon128.png', title: 'Bastion',
      message: 'Crypto miner blocked on this page!'
    });
  }
}

// --- Breach Check via HIBP Passwords API (free, k-anonymity) ---
// Checks passwords found in storage against the Pwned Passwords database.
// Uses SHA-1 prefix (5 chars) — only the prefix leaves the browser, full hash stays local.
async function handleBreachCheck(passwords, tabId) {
  const results = [];
  for (const entry of passwords) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(entry.value);
      const hashBuffer = await crypto.subtle.digest('SHA-1', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      const prefix = hashHex.substring(0, 5);
      const suffix = hashHex.substring(5);

      const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true' }
      });
      if (!resp.ok) continue;
      const text = await resp.text();
      for (const line of text.split('\n')) {
        const [hash, cnt] = line.split(':');
        if (hash.trim() === suffix) {
          results.push({
            key: entry.key,
            storage: entry.storage,
            exposures: parseInt(cnt.trim()) || 0
          });
          break;
        }
      }

      // Delay between requests to respect rate limits
      if (passwords.length > 1) await new Promise(r => setTimeout(r, 1500));
    } catch {}
  }

  if (results.length > 0) {
    addShieldEvent(tabId, {
      action: 'breachFound',
      detail: { results, timestamp: Date.now() }
    });
    chrome.notifications.create(`tg-breach-${Date.now()}`, {
      type: 'basic', iconUrl: 'icon128.png', title: 'Bastion: Leaked Password!',
      message: `${results.length} password(s) in storage found in data breaches!`
    });
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

async function runActiveSqliTest(pageUrl, params, tabId) {
  const results = [];
  if (!params || params.length === 0) return results;

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
          if (pattern.test(textSlice)) {
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
  chrome.storage.session.get('auditResults', (data) => {
    const ar = data.auditResults || {};
    if (!ar[tabId]) ar[tabId] = { passive: [], active: [] };
    ar[tabId].active = results;
    chrome.storage.session.set({ auditResults: ar });
  });

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
  chrome.storage.session.get('auditResults', (data) => {
    const ar = data.auditResults || {};
    if (!ar[tabId]) ar[tabId] = { passive: [], active: [] };
    ar[tabId].activeXss = results;
    chrome.storage.session.set({ auditResults: ar });
  });

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
        if (pt.check.test(text)) {
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

    // SQLi test
    for (const input of testInputs) {
      let found = false;
      for (const payload of FORM_SQLI_PAYLOADS) {
        if (found) break;
        try {
          const text = await sendFormPayload(form, input.name, payload);
          for (const pattern of SQL_ERROR_PATTERNS) {
            if (pattern.test(text)) {
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
          if (pt.check.test(text)) {
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
          if (cmd.check.test(text)) {
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

// Helper: send payload to a form field
async function sendFormPayload(form, targetField, payload) {
  const body = new URLSearchParams();
  for (const inp of form.inputs) {
    body.set(inp.name, inp.name === targetField ? payload : (inp.value || 'test'));
  }
  const fetchOpts = {
    credentials: 'omit', redirect: 'follow',
    signal: AbortSignal.timeout(5000)
  };
  let resp;
  if (form.method === 'POST') {
    fetchOpts.method = 'POST';
    fetchOpts.headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    fetchOpts.body = body.toString();
    resp = await fetch(form.action, fetchOpts);
  } else {
    const url = new URL(form.action);
    for (const [k, v] of body) url.searchParams.set(k, v);
    fetchOpts.method = 'GET';
    resp = await fetch(url.href, fetchOpts);
  }
  return (await resp.text()).substring(0, 50000);
}

function handleAutoScan(message, sender) {
  const tabId = sender.tab.id;
  const count = message.findings.length;
  const criticalCount = message.findings.filter(f => f.severity === 'critical').length;

  chrome.storage.session.get('headerResults', (data) => {
    const hr = (data.headerResults || {})[tabId];
    const headerGrade = hr ? hr.grade : '?';
    let finalGrade = headerGrade;
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

  if (criticalCount > 0) {
    const domain = getDomain(message.url);
    if (domain) {
      chrome.storage.session.get('notifiedDomains', (data) => {
        const notified = data.notifiedDomains || [];
        if (!notified.includes(domain)) {
          notified.push(domain);
          // Cap at 500 to prevent unbounded growth
          if (notified.length > 500) notified.splice(0, notified.length - 500);
          chrome.storage.session.set({ notifiedDomains: notified });
          chrome.notifications.create(`tg-${domain}-${Date.now()}`, {
            type: 'basic', iconUrl: 'icon128.png', title: 'Bastion',
            message: `${criticalCount} critical vulnerabilities found on ${domain}!`
          });
        }
      });
    }
  }
  saveToHistory(message.url, message.findings);
}

function saveToHistory(url, findings) {
  const domain = getDomain(url);
  if (!domain) return;
  chrome.storage.session.get('headerResults', (sessionData) => {
    let grade = '?';
    const hr = sessionData.headerResults || {};
    for (const tid of Object.keys(hr)) { if (hr[tid]) grade = hr[tid].grade; }
    const entry = { domain, date: new Date().toISOString().split('T')[0],
      tokens: findings.filter(f => f.type === 'jwt').length,
      secrets: findings.filter(f => f.type !== 'jwt' && f.severity !== 'info').length, grade };
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
  chrome.storage.session.get('exfilAlerts', (data) => {
    const alerts = data.exfilAlerts || {};
    if (!alerts[tabId]) alerts[tabId] = [];
    alerts[tabId].push(detail);
    if (alerts[tabId].length > 50) alerts[tabId] = alerts[tabId].slice(-50);
    chrome.storage.session.set({ exfilAlerts: alerts });
  });
}

// Cleanup on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.get(['headerResults', 'exfilAlerts', 'trackerCounts', 'shieldEvents', 'quantumResults', 'auditResults'], (data) => {
    const hr = data.headerResults || {}; delete hr[tabId];
    const ea = data.exfilAlerts || {}; delete ea[tabId];
    const tc = data.trackerCounts || {}; delete tc[tabId];
    const se = data.shieldEvents || {}; delete se[tabId];
    const qr = data.quantumResults || {}; delete qr[tabId];
    const ar = data.auditResults || {}; delete ar[tabId];
    chrome.storage.session.set({ headerResults: hr, exfilAlerts: ea, trackerCounts: tc, shieldEvents: se, quantumResults: qr, auditResults: ar });
  });
});
