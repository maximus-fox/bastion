/**
 * Bastion — Phishing warning page
 * background.js sends the tab here as warning.html?url=&domain=&brand=.
 * The parameters describe a hostile site, so they are only ever rendered as text.
 */
const params = new URLSearchParams(location.search);
const target = params.get('url') || '';
const domain = (params.get('domain') || '').toLowerCase();
const brand = params.get('brand') || '';
const MAX_ALLOWLIST = 500;

// Only http(s) and only the host the warning was raised for.
function targetUrl() {
  try {
    const u = new URL(target);
    if ((u.protocol === 'http:' || u.protocol === 'https:') && u.hostname === domain) return u;
  } catch {}
  return null;
}

// Fill "{domain}"/"{brand}" placeholders with <strong> text nodes.
function fillTemplate(el, template, values) {
  el.textContent = '';
  for (const part of template.split(/(\{\w+\})/)) {
    const key = part.slice(1, -1);
    if (part.startsWith('{') && key in values) {
      const strong = document.createElement('strong');
      strong.textContent = values[key];
      el.append(strong);
    } else {
      el.append(part);
    }
  }
}

function render() {
  document.title = t('warnPageTitle');
  document.getElementById('detectedBy').textContent = t('warnDetectedBy');
  document.getElementById('warnTitle').textContent = t('warnTitle');
  fillTemplate(document.getElementById('lead'), t('warnLead'), { domain: domain || '?', brand: brand || '?' });
  document.getElementById('explain').textContent = t('warnExplain');
  document.getElementById('urlLabel').textContent = t('warnUrlLabel');
  document.getElementById('url').textContent = target;
  document.getElementById('btnBack').textContent = t('warnBack');
  document.getElementById('btnContinue').textContent = t('warnContinue');
  document.getElementById('continueNote').textContent = t('warnContinueNote');
  document.getElementById('error').textContent = t('warnBadUrl');
}

function goBack() {
  // One step back is the phishing page itself, which would warn again.
  if (history.length > 2) {
    history.go(-2);
    return;
  }
  chrome.tabs.getCurrent((tab) => {
    if (tab) chrome.tabs.update(tab.id, { url: 'chrome://newtab/' });
    else location.replace('about:blank');
  });
}

async function continueToSite() {
  const u = targetUrl();
  if (!u) {
    document.getElementById('error').hidden = false;
    return;
  }
  const { phishingAllowlist } = await chrome.storage.local.get({ phishingAllowlist: [] });
  const list = (Array.isArray(phishingAllowlist) ? phishingAllowlist : [])
    .filter((h) => typeof h === 'string' && h !== u.hostname);
  list.push(u.hostname);
  await chrome.storage.local.set({ phishingAllowlist: list.slice(-MAX_ALLOWLIST) });
  location.replace(u.href);
}

document.getElementById('btnBack').addEventListener('click', goBack);
document.getElementById('btnContinue').addEventListener('click', continueToSite);

applyLang(defaultLang());
render();
chrome.storage.local.get('lang', (data) => {
  if (data.lang && data.lang !== currentLang) {
    applyLang(data.lang);
    render();
  }
});
