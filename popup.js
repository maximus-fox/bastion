// --- Bastion inline icon set (Tabler Icons, MIT). Local, CSP-safe. ---
const ICON_PATHS = {
  'alert-octagon': '<path d="M12.802 2.165l5.575 2.389c.48 .206 .863 .589 1.07 1.07l2.388 5.574c.22 .512 .22 1.092 0 1.604l-2.389 5.575c-.206 .48 -.589 .863 -1.07 1.07l-5.574 2.388c-.512 .22 -1.092 .22 -1.604 0l-5.575 -2.389a2.036 2.036 0 0 1 -1.07 -1.07l-2.388 -5.574a2.036 2.036 0 0 1 0 -1.604l2.389 -5.575c.206 -.48 .589 -.863 1.07 -1.07l5.574 -2.388a2.036 2.036 0 0 1 1.604 0z" /><path d="M12 8v4" /><path d="M12 16h.01" />',
  'alert-triangle': '<path d="M12 9v4" /><path d="M10.363 3.591l-8.106 13.534a1.914 1.914 0 0 0 1.636 2.871h16.214a1.914 1.914 0 0 0 1.636 -2.87l-8.106 -13.536a1.914 1.914 0 0 0 -3.274 0z" /><path d="M12 16h.01" />',
  'arrow-forward-up': '<path d="M15 14l4 -4l-4 -4" /><path d="M19 10h-11a4 4 0 1 0 0 8h1" />',
  'arrows-shuffle': '<path d="M18 4l3 3l-3 3" /><path d="M18 20l3 -3l-3 -3" /><path d="M3 7h3a5 5 0 0 1 5 5a5 5 0 0 0 5 5h5" /><path d="M21 7h-5a4.978 4.978 0 0 0 -3 1m-4 8a4.984 4.984 0 0 1 -3 1h-3" />',
  'atom-2': '<path d="M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0" /><path d="M12 21l0 .01" /><path d="M3 9l0 .01" /><path d="M21 9l0 .01" /><path d="M8 20.1a9 9 0 0 1 -5 -7.1" /><path d="M16 20.1a9 9 0 0 0 5 -7.1" /><path d="M6.2 5a9 9 0 0 1 11.4 0" />',
  'bolt': '<path d="M13 3l0 7l6 0l-8 11l0 -7l-6 0l8 -11" />',
  'brand-telegram': '<path d="M15 10l-4 4l6 6l4 -16l-18 7l4 2l2 6l3 -4" />',
  'bulb': '<path d="M3 12h1m8 -9v1m8 8h1m-15.4 -6.4l.7 .7m12.1 -.7l-.7 .7" /><path d="M9 16a5 5 0 1 1 6 0a3.5 3.5 0 0 0 -1 3a2 2 0 0 1 -4 0a3.5 3.5 0 0 0 -1 -3" /><path d="M9.7 17l4.6 0" />',
  'check': '<path d="M5 12l5 5l10 -10" />',
  'circle-check': '<path d="M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0" /><path d="M9 12l2 2l4 -4" />',
  'circle-x': '<path d="M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0" /><path d="M10 10l4 4m0 -4l-4 4" />',
  'clipboard': '<path d="M9 5h-2a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-12a2 2 0 0 0 -2 -2h-2" /><path d="M9 3m0 2a2 2 0 0 1 2 -2h2a2 2 0 0 1 2 2v0a2 2 0 0 1 -2 2h-2a2 2 0 0 1 -2 -2z" />',
  'clipboard-check': '<path d="M9 5h-2a2 2 0 0 0 -2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2 -2v-12a2 2 0 0 0 -2 -2h-2" /><path d="M9 3m0 2a2 2 0 0 1 2 -2h2a2 2 0 0 1 2 2v0a2 2 0 0 1 -2 2h-2a2 2 0 0 1 -2 -2z" /><path d="M9 14l2 2l4 -4" />',
  'clock': '<path d="M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0" /><path d="M12 7v5l3 3" />',
  'code': '<path d="M7 8l-4 4l4 4" /><path d="M17 8l4 4l-4 4" /><path d="M14 4l-4 16" />',
  'coffee': '<path d="M3 14c.83 .642 2.077 1.017 3.5 1c1.423 .017 2.67 -.358 3.5 -1c.83 -.642 2.077 -1.017 3.5 -1c1.423 -.017 2.67 .358 3.5 1" /><path d="M8 3a2.4 2.4 0 0 0 -1 2a2.4 2.4 0 0 0 1 2" /><path d="M12 3a2.4 2.4 0 0 0 -1 2a2.4 2.4 0 0 0 1 2" /><path d="M3 10h14v5a6 6 0 0 1 -6 6h-2a6 6 0 0 1 -6 -6v-5z" /><path d="M16.746 16.726a3 3 0 1 0 .252 -5.555" />',
  'coin': '<path d="M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0" /><path d="M14.8 9a2 2 0 0 0 -1.8 -1h-2a2 2 0 1 0 0 4h2a2 2 0 1 1 0 4h-2a2 2 0 0 1 -1.8 -1" /><path d="M12 7v10" />',
  'cookie': '<path d="M8 13v.01" /><path d="M12 17v.01" /><path d="M12 12v.01" /><path d="M16 14v.01" /><path d="M11 8v.01" /><path d="M13.148 3.476l2.667 1.104a4 4 0 0 0 4.656 6.14l.053 .132a3 3 0 0 1 0 2.296q -.745 1.18 -1.024 1.852q -.283 .684 -.66 2.216a3 3 0 0 1 -1.624 1.623q -1.572 .394 -2.216 .661q -.712 .295 -1.852 1.024a3 3 0 0 1 -2.296 0q -1.203 -.754 -1.852 -1.024q -.707 -.292 -2.216 -.66a3 3 0 0 1 -1.623 -1.624q -.397 -1.577 -.661 -2.216q -.298 -.718 -1.024 -1.852a3 3 0 0 1 0 -2.296q .719 -1.116 1.024 -1.852q .257 -.62 .66 -2.216a3 3 0 0 1 1.624 -1.623q 1.547 -.384 2.216 -.661q .687 -.285 1.852 -1.024a3 3 0 0 1 2.296 0" />',
  'credit-card': '<path d="M3 5m0 3a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v8a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3z" /><path d="M3 10l18 0" /><path d="M7 15l.01 0" /><path d="M11 15l2 0" />',
  'currency-bitcoin': '<path d="M6 6h8a3 3 0 0 1 0 6a3 3 0 0 1 0 6h-8" /><path d="M8 6l0 12" /><path d="M8 12l6 0" /><path d="M9 3l0 3" /><path d="M13 3l0 3" /><path d="M9 18l0 3" /><path d="M13 18l0 3" />',
  'currency-ethereum': '<path d="M6 12l6 -9l6 9l-6 9z" /><path d="M6 12l6 -3l6 3l-6 2z" />',
  'eye': '<path d="M10 12a2 2 0 1 0 4 0a2 2 0 0 0 -4 0" /><path d="M21 12c-2.4 4 -5.4 6 -9 6c-3.6 0 -6.6 -2 -9 -6c2.4 -4 5.4 -6 9 -6c3.6 0 6.6 2 9 6" />',
  'file-info': '<path d="M14 3v4a1 1 0 0 0 1 1h4" /><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z" /><path d="M11 14h1v4h1" /><path d="M12 11h.01" />',
  'file-text': '<path d="M14 3v4a1 1 0 0 0 1 1h4" /><path d="M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z" /><path d="M9 9l1 0" /><path d="M9 13l6 0" /><path d="M9 17l6 0" />',
  'fingerprint': '<path d="M18.9 7a8 8 0 0 1 1.1 5v1a6 6 0 0 0 .8 3" /><path d="M8 11a4 4 0 0 1 8 0v1a10 10 0 0 0 2 6" /><path d="M12 11v2a14 14 0 0 0 2.5 8" /><path d="M8 15a18 18 0 0 0 1.8 6" /><path d="M4.9 19a22 22 0 0 1 -.9 -7v-1a8 8 0 0 1 12 -6.95" />',
  'fish': '<path d="M16.69 7.44a6.973 6.973 0 0 0 -1.69 4.56c0 1.747 .64 3.345 1.699 4.571" /><path d="M2 9.504c7.715 8.647 14.75 10.265 20 2.498c-5.25 -7.761 -12.285 -6.142 -20 2.504" /><path d="M18 11v.01" /><path d="M11.5 10.5c-.667 1 -.667 2 0 3" />',
  'folder': '<path d="M5 4h4l3 3h7a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2v-11a2 2 0 0 1 2 -2" />',
  'hand-stop': '<path d="M8 13v-7.5a1.5 1.5 0 0 1 3 0v6.5" /><path d="M11 5.5v-2a1.5 1.5 0 1 1 3 0v8.5" /><path d="M14 5.5a1.5 1.5 0 0 1 3 0v6.5" /><path d="M17 7.5a1.5 1.5 0 0 1 3 0v8.5a6 6 0 0 1 -6 6h-2h.208a6 6 0 0 1 -5.012 -2.7a69.74 69.74 0 0 1 -.196 -.3c-.312 -.479 -1.407 -2.388 -3.286 -5.728a1.5 1.5 0 0 1 .536 -2.022a1.867 1.867 0 0 1 2.28 .28l1.47 1.47" />',
  'heart-handshake': '<path d="M19.5 12.572l-7.5 7.428l-7.5 -7.428a5 5 0 1 1 7.5 -6.566a5 5 0 1 1 7.5 6.572" /><path d="M12 6l-3.293 3.293a1 1 0 0 0 0 1.414l.543 .543c.69 .69 1.81 .69 2.5 0l1 -1a3.182 3.182 0 0 1 4.5 0l2.25 2.25" /><path d="M12.5 15.5l2 2" /><path d="M15 13l2 2" />',
  'help': '<path d="M12 12m-9 0a9 9 0 1 0 18 0a9 9 0 1 0 -18 0" /><path d="M12 17l0 .01" /><path d="M12 13.5a1.5 1.5 0 0 1 1 -1.5a2.6 2.6 0 1 0 -3 -4" />',
  'history': '<path d="M12 8l0 4l2 2" /><path d="M3.05 11a9 9 0 1 1 .5 4m-.5 5v-5h5" />',
  'keyboard': '<path d="M2 6m0 2a2 2 0 0 1 2 -2h16a2 2 0 0 1 2 2v8a2 2 0 0 1 -2 2h-16a2 2 0 0 1 -2 -2z" /><path d="M6 10l0 .01" /><path d="M10 10l0 .01" /><path d="M14 10l0 .01" /><path d="M18 10l0 .01" /><path d="M6 14l0 .01" /><path d="M18 14l0 .01" /><path d="M10 14l4 .01" />',
  'link': '<path d="M9 15l6 -6" /><path d="M11 6l.463 -.536a5 5 0 0 1 7.071 7.072l-.534 .464" /><path d="M13 18l-.397 .534a5.068 5.068 0 0 1 -7.127 0a4.972 4.972 0 0 1 0 -7.071l.524 -.463" />',
  'list': '<path d="M9 6l11 0" /><path d="M9 12l11 0" /><path d="M9 18l11 0" /><path d="M5 6l0 .01" /><path d="M5 12l0 .01" /><path d="M5 18l0 .01" />',
  'list-details': '<path d="M13 5h8" /><path d="M13 9h5" /><path d="M13 15h8" /><path d="M13 19h5" /><path d="M3 4m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z" /><path d="M3 14m0 1a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v4a1 1 0 0 1 -1 1h-4a1 1 0 0 1 -1 -1z" />',
  'lock': '<path d="M5 13a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2v-6z" /><path d="M11 16a1 1 0 1 0 2 0a1 1 0 0 0 -2 0" /><path d="M8 11v-4a4 4 0 1 1 8 0v4" />',
  'lock-open': '<path d="M5 11m0 2a2 2 0 0 1 2 -2h10a2 2 0 0 1 2 2v6a2 2 0 0 1 -2 2h-10a2 2 0 0 1 -2 -2z" /><path d="M12 16m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0" /><path d="M8 11v-5a4 4 0 0 1 8 0" />',
  'palette': '<path d="M12 21a9 9 0 0 1 0 -18c4.97 0 9 3.582 9 8c0 1.06 -.474 2.078 -1.318 2.828c-.844 .75 -1.989 1.172 -3.182 1.172h-2.5a2 2 0 0 0 -1 3.75a1.3 1.3 0 0 1 -1 2.25" /><path d="M8.5 10.5m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0" /><path d="M12.5 7.5m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0" /><path d="M16.5 10.5m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0" />',
  'photo': '<path d="M15 8h.01" /><path d="M3 6a3 3 0 0 1 3 -3h12a3 3 0 0 1 3 3v12a3 3 0 0 1 -3 3h-12a3 3 0 0 1 -3 -3v-12z" /><path d="M3 16l5 -5c.928 -.893 2.072 -.893 3 0l5 5" /><path d="M14 14l1 -1c.928 -.893 2.072 -.893 3 0l3 3" />',
  'pick': '<path d="M13 8l-9.383 9.418a2.091 2.091 0 0 0 0 2.967a2.11 2.11 0 0 0 2.976 0l9.407 -9.385" /><path d="M9 3h4.586a1 1 0 0 1 .707 .293l6.414 6.414a1 1 0 0 1 .293 .707v4.586a2 2 0 1 1 -4 0v-3l-5 -5h-3a2 2 0 1 1 0 -4z" />',
  'radar-2': '<path d="M12 12m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0" /><path d="M15.51 15.56a5 5 0 1 0 -3.51 1.44" /><path d="M18.832 17.86a9 9 0 1 0 -6.832 3.14" /><path d="M12 12v9" />',
  'search': '<path d="M10 10m-7 0a7 7 0 1 0 14 0a7 7 0 1 0 -14 0" /><path d="M21 21l-6 -6" />',
  'settings': '<path d="M10.325 4.317c.426 -1.756 2.924 -1.756 3.35 0a1.724 1.724 0 0 0 2.573 1.066c1.543 -.94 3.31 .826 2.37 2.37a1.724 1.724 0 0 0 1.065 2.572c1.756 .426 1.756 2.924 0 3.35a1.724 1.724 0 0 0 -1.066 2.573c.94 1.543 -.826 3.31 -2.37 2.37a1.724 1.724 0 0 0 -2.572 1.065c-.426 1.756 -2.924 1.756 -3.35 0a1.724 1.724 0 0 0 -2.573 -1.066c-1.543 .94 -3.31 -.826 -2.37 -2.37a1.724 1.724 0 0 0 -1.065 -2.572c-1.756 -.426 -1.756 -2.924 0 -3.35a1.724 1.724 0 0 0 1.066 -2.573c-.94 -1.543 .826 -3.31 2.37 -2.37c1 .608 2.296 .07 2.572 -1.065z" /><path d="M9 12a3 3 0 1 0 6 0a3 3 0 0 0 -6 0" />',
  'shield-half': '<path d="M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3" /><path d="M12 3v18" />',
  'shield-lock': '<path d="M12 3a12 12 0 0 0 8.5 3a12 12 0 0 1 -8.5 15a12 12 0 0 1 -8.5 -15a12 12 0 0 0 8.5 -3" /><path d="M12 11m-1 0a1 1 0 1 0 2 0a1 1 0 1 0 -2 0" /><path d="M12 12l0 2.5" />',
  'terminal-2': '<path d="M8 9l3 3l-3 3" /><path d="M13 15l3 0" /><path d="M3 4m0 2a2 2 0 0 1 2 -2h14a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-14a2 2 0 0 1 -2 -2z" />',
  'trash': '<path d="M4 7l16 0" /><path d="M10 11l0 6" /><path d="M14 11l0 6" /><path d="M5 7l1 12a2 2 0 0 0 2 2h8a2 2 0 0 0 2 -2l1 -12" /><path d="M9 7v-3a1 1 0 0 1 1 -1h4a1 1 0 0 1 1 1v3" />',
  'user': '<path d="M8 7a4 4 0 1 0 8 0a4 4 0 0 0 -8 0" /><path d="M6 21v-2a4 4 0 0 1 4 -4h4a4 4 0 0 1 4 4v2" />',
  'world': '<path d="M3 12a9 9 0 1 0 18 0a9 9 0 0 0 -18 0" /><path d="M3.6 9h16.8" /><path d="M3.6 15h16.8" /><path d="M11.5 3a17 17 0 0 0 0 18" /><path d="M12.5 3a17 17 0 0 1 0 18" />',
  'x': '<path d="M18 6l-12 12" /><path d="M6 6l12 12" />',
};
const ICON_ALIAS = {
  'shield': 'shield-half',
  'ok': 'circle-check',
  'warn': 'alert-triangle',
  'lock': 'lock',
  'unlock': 'lock-open',
  'form': 'file-text',
  'globe': 'world',
  'eye': 'eye',
  'fingerprint': 'fingerprint',
  'tip': 'bulb',
  'card': 'credit-card',
  'x': 'circle-x',
  'phishing': 'fish',
  'miner': 'pick',
  'cookie': 'cookie',
  'link': 'link',
  'clipboard': 'clipboard',
  'xss': 'code',
  'ssti': 'palette',
  'path': 'folder',
  'cmdi': 'terminal-2',
  'csrf': 'arrows-shuffle',
  'idor': 'user',
  'redirect': 'arrow-forward-up',
  'clickjack': 'photo',
  'infodisc': 'file-info',
  'trash': 'trash',
  'alarm': 'alert-octagon',
  'check': 'check',
  'cross': 'x',
  'help': 'help',
  'bolt': 'bolt',
  'log': 'list',
  'stop': 'hand-stop',
  'settings': 'settings',
  'search': 'search',
  'btc': 'currency-bitcoin',
  'eth': 'currency-ethereum',
  'usdt': 'coin',
  'coffee': 'coffee',
  'donate': 'heart-handshake',
  'telegram': 'brand-telegram',
  'radar': 'radar-2',
  'audit': 'clipboard-check',
  'quantum': 'atom-2',
  'history': 'history',
  'protect': 'shield-lock',
  'headers': 'list-details',
  'clock': 'clock',
  'keyboard': 'keyboard',
};

function svgIcon(name, size) {
  const key = ICON_ALIAS[name] || name;
  const inner = ICON_PATHS[key] || '';
  const s = size || 20;
  return '<svg class="bic" width="'+s+'" height="'+s+'" viewBox="0 0 24 24" fill="none" '
    + 'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" '
    + 'aria-hidden="true">'+inner+'</svg>';
}
/**
 * TokenGuard v2.0 — Popup Logic with i18n (RU/EN)
 */

const siteUrl = document.getElementById('siteUrl');
const scannerContent = document.getElementById('scannerContent');
const headersContent = document.getElementById('headersContent');
const historyContent = document.getElementById('historyContent');
const protectContent = document.getElementById('protectContent');
const quantumContent = document.getElementById('quantumContent');
const auditContent = document.getElementById('auditContent');
const toastEl = document.getElementById('toast');
const langBtn = document.getElementById('langBtn');

let currentTabId = null;

// --- Tabs ---
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// --- Language switcher ---
langBtn.addEventListener('click', () => {
  const newLang = currentLang === 'ru' ? 'en' : 'ru';
  setLang(newLang);
  updateUI();
});

// --- Utils ---
function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function formatDate(timestamp) {
  if (!timestamp) return '?';
  const locale = currentLang === 'ru' ? 'ru-RU' : 'en-US';
  return new Date(timestamp * 1000).toLocaleString(locale);
}

function showToast(text) {
  toastEl.textContent = text;
  toastEl.classList.add('show');
  setTimeout(() => toastEl.classList.remove('show'), 1500);
}

// Suppress "message port closed" errors
function msgBg(msg, cb) {
  chrome.runtime.sendMessage(msg, (resp) => {
    if (chrome.runtime.lastError) { cb && cb(null); return; }
    cb && cb(resp);
  });
}
function msgTab(tabId, msg, cb) {
  chrome.tabs.sendMessage(tabId, msg, (resp) => {
    if (chrome.runtime.lastError) { cb && cb(null); return; }
    cb && cb(resp);
  });
}

// --- Update all UI with current language ---
function updateUI() {
  langBtn.textContent = currentLang.toUpperCase();
  document.getElementById('headerSub').textContent = t('subtitle');
  ['Scanner','Headers','History','Quantum','Protect','Audit'].forEach(n => {
    const el = document.getElementById('tab' + n);
    if (el) { el.title = t('tab' + n); el.setAttribute('aria-label', t('tab' + n)); }
  });

  loadScanner();
  loadHeaders();
  loadHistory();
  loadQuantum();
  loadProtect();
  loadAudit();
}

// --- Scanner Tab ---
function renderScanner(data) {
  const { findings, url } = data;
  siteUrl.textContent = url;

  if (!findings || findings.length === 0) {
    scannerContent.innerHTML = `
      <div class="status safe">
        <span class="status-icon">${svgIcon('ok')}</span>
        <div>
          <div class="status-text">${t('safe')}</div>
          <div class="status-sub">${t('safeSub')}</div>
        </div>
      </div>`;
    // Header tips even when storage is clean
    msgBg({ action: 'getHeaderResults', tabId: currentTabId }, (hr) => {
      if (hr && hr.missing && hr.missing.length > 0) {
        let html = `<div class="tips-section"><div class="tips-title">${svgIcon('tip')} ${t('tipsSiteTitle')}</div>`;
        if (hr.missing.includes('content-security-policy')) {
          html += `<div class="tip tip-warning"><span class="tip-icon">${svgIcon('shield')}</span><span>${t('tipNoCsp')}</span></div>`;
        }
        if (hr.missing.includes('strict-transport-security')) {
          html += `<div class="tip tip-warning"><span class="tip-icon">${svgIcon('unlock')}</span><span>${t('tipNoHsts')}</span></div>`;
        }
        if (hr.missing.includes('referrer-policy')) {
          html += `<div class="tip tip-info"><span class="tip-icon">${svgIcon('eye')}</span><span>${t('tipNoReferrer')}</span></div>`;
        }
        html += '</div>';
        scannerContent.insertAdjacentHTML('beforeend', html);
      }
    });
    return;
  }

  const critical = findings.filter(f => f.severity === 'critical').length;
  const warns = findings.filter(f => f.severity === 'warning').length;
  const statusClass = critical > 0 ? 'danger' : warns > 0 ? 'warning' : 'safe';
  const statusIcon = critical > 0 ? svgIcon('warn') : warns > 0 ? svgIcon('warn') : svgIcon('ok');

  let html = `
    <div class="status ${statusClass}">
      <span class="status-icon">${statusIcon}</span>
      <div>
        <div class="status-text">${t('found')}: ${findings.length}</div>
        <div class="status-sub">${critical} ${t('critical')}, ${warns} ${t('warnings')}</div>
      </div>
    </div>
    <div class="findings">`;

  for (const f of findings) {
    const p = f.payload || {};
    const isExpired = f.expired;
    const expClass = isExpired === true ? 'expired' : isExpired === false ? 'valid' : '';
    const expText = isExpired === true ? t('expired') : isExpired === false ? t('active') : '?';

    html += `
      <div class="finding">
        <div class="finding-header">
          <span class="finding-key ${f.severity}">${escapeHtml(f.key)}</span>
          <div class="finding-badges">
            <span class="badge badge-type">${escapeHtml(f.label)}</span>
            <span class="badge badge-storage">${escapeHtml(f.storage)}</span>
            <button class="btn-delete" data-key="${escapeHtml(f.key)}" data-storage="${escapeHtml(f.storage)}">${svgIcon('trash')} ${t('btnDelete')}</button>
          </div>
        </div>
        <div class="finding-token">${escapeHtml(f.token)}</div>`;

    if (f.type === 'jwt' && p) {
      html += '<div class="payload-grid">';
      if (p.sub) html += `<span class="payload-key">user_id:</span><span class="payload-val">${escapeHtml(String(p.sub))}</span>`;
      if (p.username) html += `<span class="payload-key">username:</span><span class="payload-val">${escapeHtml(p.username)}</span>`;
      if (p.email) html += `<span class="payload-key">email:</span><span class="payload-val">${escapeHtml(p.email)}</span>`;
      if (p.role) html += `<span class="payload-key">role:</span><span class="payload-val">${escapeHtml(p.role)}</span>`;
      if (p.iss) html += `<span class="payload-key">issuer:</span><span class="payload-val">${escapeHtml(p.iss)}</span>`;
      if (p.iat) html += `<span class="payload-key">issued:</span><span class="payload-val">${formatDate(p.iat)}</span>`;
      if (p.exp) html += `<span class="payload-key">expires:</span><span class="payload-val ${expClass}">${formatDate(p.exp)} (${expText})</span>`;
      html += '</div>';
    }

    html += '</div>';
  }

  html += '</div>';
  scannerContent.innerHTML = html;

  // Delete buttons
  scannerContent.querySelectorAll('.btn-delete').forEach(btn => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.key;
      const storage = btn.dataset.storage;
      msgTab(currentTabId, { action: 'removeItem', key, storage }, (resp) => {
        if (resp && resp.success) {
          showToast(t('deleted') + ': ' + key);
          setTimeout(() => loadScanner(), 300);
        } else {
          showToast(t('deleteError'));
        }
      });
    });
  });

  // Tips
  const tips = [];
  for (const f of findings) {
    if (f.type === 'jwt' && f.expired === true) {
      tips.push({ icon: svgIcon('clock'), text: `<b>${escapeHtml(f.key)}</b> ${t('tipExpiredJwt')}`, severity: 'warning' });
    } else if (f.type === 'jwt' && f.expired === false) {
      tips.push({ icon: svgIcon('warn'), text: `<b>${escapeHtml(f.key)}</b> ${t('tipActiveJwt')}`, severity: 'critical' });
    }
    if (f.type === 'api_key') {
      tips.push({ icon: svgIcon('alarm'), text: `<b>${escapeHtml(f.key)}</b> ${t('tipApiKey')}`, severity: 'critical' });
    }
    if (f.type === 'password') {
      tips.push({ icon: svgIcon('lock'), text: `<b>${escapeHtml(f.key)}</b> ${t('tipPassword')}`, severity: 'warning' });
    }
    if (f.type === 'card') {
      tips.push({ icon: svgIcon('card'), text: `<b>${escapeHtml(f.key)}</b> — ${t('tipCard')}`, severity: 'critical' });
    }
  }

  msgBg({ action: 'getHeaderResults', tabId: currentTabId }, (hr) => {
    if (hr && hr.missing && hr.missing.length > 0) {
      if (hr.missing.includes('content-security-policy')) {
        tips.push({ icon: svgIcon('shield'), text: t('tipNoCsp'), severity: 'warning' });
      }
      if (hr.missing.includes('strict-transport-security')) {
        tips.push({ icon: svgIcon('unlock'), text: t('tipNoHsts'), severity: 'warning' });
      }
    }

    if (tips.length > 0) {
      let tipsHtml = `<div class="tips-section"><div class="tips-title">${svgIcon('tip')} ${t('tipsTitle')}</div>`;
      for (const tip of tips) {
        tipsHtml += `<div class="tip tip-${tip.severity}"><span class="tip-icon">${tip.icon}</span><span>${tip.text}</span></div>`;
      }
      tipsHtml += '</div>';
      scannerContent.insertAdjacentHTML('beforeend', tipsHtml);
    }
  });

  // Action prompts — интерактивные предложения
  buildActionPrompts(findings);

  // Exfil alerts
  msgBg({ action: 'getExfilAlerts', tabId: currentTabId }, (alerts) => {
    if (!alerts || alerts.length === 0) return;
    let exHtml = `<div class="exfil-section">
      <div class="exfil-title">${svgIcon('warn')} ${t('exfilTitle')}: ${alerts.length}</div>`;
    for (const a of alerts.slice(-5)) {
      const blockedTag = a.blocked ? ` <span class="protect-blocked-badge">${t('exfilBlocked')}</span>` : '';
      exHtml += `<div class="exfil-item">${escapeHtml(a.method.toUpperCase())} \u2192 ${escapeHtml(a.url)}${blockedTag}</div>`;
    }
    exHtml += '</div>';
    scannerContent.insertAdjacentHTML('beforeend', exHtml);
  });
}

function buildActionPrompts(findings) {
  const expiredJwts = findings.filter(f => f.type === 'jwt' && f.expired === true);
  const cards = findings.filter(f => f.type === 'card');

  let html = '';

  // Предложение удалить истёкшие JWT
  if (expiredJwts.length > 0) {
    html += `
      <div class="action-prompt warning" id="promptExpired">
        <div class="action-prompt-icon">${svgIcon('clock')}</div>
        <div class="action-prompt-text">${t('actionDeleteExpired')}</div>
        <div class="action-prompt-desc">${t('actionDeleteExpiredDesc')} (${expiredJwts.length})</div>
        <div class="action-btns">
          <button class="action-btn action-btn-yes" id="btnDeleteExpired">${t('actionYes')}</button>
          <button class="action-btn action-btn-no" id="btnSkipExpired">${t('actionNo')}</button>
        </div>
      </div>`;
  }

  // Предложение удалить номера карт
  if (cards.length > 0) {
    html += `
      <div class="action-prompt critical" id="promptCard">
        <div class="action-prompt-icon">${svgIcon('card')}</div>
        <div class="action-prompt-text">${t('actionDeleteCard')}</div>
        <div class="action-prompt-desc">${t('actionDeleteCardDesc')}</div>
        <div class="action-btns">
          <button class="action-btn action-btn-yes" id="btnDeleteCards">${t('actionYes')}</button>
          <button class="action-btn action-btn-no" id="btnSkipCards">${t('actionNo')}</button>
        </div>
      </div>`;
  }

  if (!html) return;
  scannerContent.insertAdjacentHTML('beforeend', html);

  // Обработчики
  const btnDelExpired = document.getElementById('btnDeleteExpired');
  const btnSkipExpired = document.getElementById('btnSkipExpired');
  if (btnDelExpired) {
    btnDelExpired.addEventListener('click', () => {
      let count = 0;
      let done = 0;
      for (const f of expiredJwts) {
        msgTab(currentTabId, { action: 'removeItem', key: f.key, storage: f.storage }, () => {
          count++;
          done++;
          if (done === expiredJwts.length) {
            showToast(`${t('actionDeletedN')}: ${count}`);
            setTimeout(() => loadScanner(), 300);
          }
        });
      }
    });
    btnSkipExpired.addEventListener('click', () => {
      document.getElementById('promptExpired').remove();
    });
  }

  const btnDelCards = document.getElementById('btnDeleteCards');
  const btnSkipCards = document.getElementById('btnSkipCards');
  if (btnDelCards) {
    btnDelCards.addEventListener('click', () => {
      let done = 0;
      for (const f of cards) {
        msgTab(currentTabId, { action: 'removeItem', key: f.key, storage: f.storage }, () => {
          done++;
          if (done === cards.length) {
            showToast(t('actionDone'));
            setTimeout(() => loadScanner(), 300);
          }
        });
      }
    });
    btnSkipCards.addEventListener('click', () => {
      document.getElementById('promptCard').remove();
    });
  }

  // Предложение включить блокировку утечек (если есть exfil alerts и блокировка выключена)
  msgBg({ action: 'getExfilAlerts', tabId: currentTabId }, (alerts) => {
    if (!alerts || alerts.length === 0) return;
    msgBg({ action: 'getSettings' }, (settings) => {
      if (!settings || settings.blockExfil) return;
      const promptHtml = `
        <div class="action-prompt warning" id="promptBlock">
          <div class="action-prompt-icon">${svgIcon('shield')}</div>
          <div class="action-prompt-text">${t('actionEnableBlock')}</div>
          <div class="action-prompt-desc">${t('actionEnableBlockDesc')}</div>
          <div class="action-btns">
            <button class="action-btn action-btn-yes" id="btnEnableBlock">${t('actionYes')}</button>
            <button class="action-btn action-btn-no" id="btnSkipBlock">${t('actionNo')}</button>
          </div>
        </div>`;
      scannerContent.insertAdjacentHTML('beforeend', promptHtml);
      document.getElementById('btnEnableBlock').addEventListener('click', () => {
        msgBg({ action: 'setSettings', settings: { ...settings, blockExfil: true } }, () => {
          showToast(t('settBlockExfilOn'));
          document.getElementById('promptBlock').remove();
        });
      });
      document.getElementById('btnSkipBlock').addEventListener('click', () => {
        document.getElementById('promptBlock').remove();
      });
    });
  });
}

function loadScanner() {
  msgTab(currentTabId, { action: 'scan' }, (response) => {
    if (!response) {
      scannerContent.innerHTML = `
        <div class="status safe">
          <span class="status-icon">${svgIcon('lock')}</span>
          <div>
            <div class="status-text">${t('noAccess')}</div>
            <div class="status-sub">${t('noAccessSub')}</div>
          </div>
        </div>`;
      return;
    }
    renderScanner(response);
  });
}

// --- Headers Tab ---
function loadHeaders() {
  msgBg({ action: 'getHeaderResults', tabId: currentTabId }, (result) => {
    if (!result) {
      headersContent.innerHTML = `<div class="loading">${t('headersNotLoaded')}</div>`;
      return;
    }

    const HEADER_DISPLAY = {
      'strict-transport-security': { name: 'Strict-Transport-Security (HSTS)', descKey: 'headerDescHsts' },
      'content-security-policy': { name: 'Content-Security-Policy (CSP)', descKey: 'headerDescCsp' },
      'x-frame-options': { name: 'X-Frame-Options', descKey: 'headerDescXfo' },
      'x-content-type-options': { name: 'X-Content-Type-Options', descKey: 'headerDescXcto' },
      'x-xss-protection': { name: 'X-XSS-Protection', descKey: 'headerDescXxss' },
      'referrer-policy': { name: 'Referrer-Policy', descKey: 'headerDescRp' }
    };

    let html = `
      <div class="grade-box">
        <div class="grade-letter grade-${result.grade}">${result.grade}</div>
        <div class="grade-label">${t('securityHeaders')}: ${result.found.length}/6</div>
        <div class="grade-desc">${gradeDesc(result.grade)}</div>
      </div>
      <div class="headers-list">`;

    const allHeaders = [
      'strict-transport-security', 'content-security-policy', 'x-frame-options',
      'x-content-type-options', 'x-xss-protection', 'referrer-policy'
    ];

    for (const h of allHeaders) {
      const present = result.found.includes(h);
      const value = result.headers[h] || '';
      const info = HEADER_DISPLAY[h];
      const statusColor = present ? 'header-status-ok' : 'header-status-miss';
      const statusLabel = present ? t('headerPresent') : t('headerMissing');

      html += `
        <div class="header-row">
          <div>
            <span class="header-name">${info.name}</span>
            <div class="header-human">${t(info.descKey)}</div>
            ${present ? `<div class="header-value" title="${escapeHtml(value)}">${escapeHtml(value)}</div>` : ''}
          </div>
          <div class="header-status-label">
            <span class="${statusColor}">${present ? svgIcon('check') : svgIcon('cross')}</span>
            <div class="${statusColor}" style="font-size:9px">${statusLabel}</div>
          </div>
        </div>`;
    }

    html += '</div>';
    headersContent.innerHTML = html;
  });
}

// --- History Tab ---
function loadHistory() {
  msgBg({ action: 'getHistory' }, (history) => {
    if (!history || history.length === 0) {
      historyContent.innerHTML = `<div class="loading">${t('historyEmpty')}</div>`;
      return;
    }

    const total = history.length;
    const unsafe = history.filter(h => h.tokens > 0 || h.secrets > 0).length;
    const safe = total - unsafe;

    let html = `
      <div class="history-stats">
        ${t('historyChecked')} <strong>${total}</strong> ${t('historySites')}: <strong>${safe}</strong> ${t('historySafe')}, <strong>${unsafe}</strong> ${t('historyUnsafe')}
      </div>
      <div class="history-wrap">
        <table class="history-table">
          <thead><tr>
            <th>${t('histDomain')}</th>
            <th>${t('histDate')}</th>
            <th>${t('histJwt')}</th>
            <th>${t('histSecrets')}</th>
            <th>${t('histGrade')}</th>
          </tr></thead>
          <tbody>`;

    for (const h of history) {
      const gradeClass = 'grade-' + h.grade;
      html += `<tr>
        <td>${escapeHtml(h.domain)}</td>
        <td>${escapeHtml(h.date)}</td>
        <td>${h.tokens || 0}</td>
        <td>${h.secrets || 0}</td>
        <td class="${gradeClass}">${h.grade}</td>
      </tr>`;
    }

    html += '</tbody></table></div>';
    historyContent.innerHTML = html;
  });
}

// --- Quantum Tab ---
function loadQuantum() {
  msgBg({ action: 'getQuantumStatus', tabId: currentTabId }, (qInfo) => {
    chrome.tabs.get(currentTabId, (tab) => {
      if (chrome.runtime.lastError || !tab) {
        renderQuantum(qInfo, tab);
        return;
      }

      // Auto-detect TLS info if not yet determined
      if (!qInfo || qInfo.pqStatus === 'unknown') {
        msgTab(currentTabId, { action: 'detectTLS' }, (result) => {
          if (chrome.runtime.lastError) result = null;
          const secInfo = result && result.protocol
            ? { keyExchange: result.keyExchange || 'ECDHE', cipher: result.cipher || 'AES-256-GCM', protocol: result.protocol }
            : (tab.url && tab.url.startsWith('https://') ? { keyExchange: 'ECDHE', cipher: 'AES-256-GCM', protocol: 'TLS 1.3' } : null);
          if (secInfo) {
            msgBg({ action: 'reportSecurityInfo', tabId: currentTabId, securityInfo: secInfo }, () => {
              msgBg({ action: 'getQuantumStatus', tabId: currentTabId }, (updated) => {
                renderQuantum(updated, tab);
              });
            });
          } else {
            renderQuantum(qInfo, tab);
          }
        });
      } else {
        renderQuantum(qInfo, tab);
      }
    });
  });
}

function renderQuantum(qInfo, tab, secInfo) {
  const url = (tab && tab.url) || '';
  const isHttps = url.startsWith('https://');
  const isHttp = url.startsWith('http://');
  const isChromeInternal = url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:');

  // Determine PQ status
  let pqStatus = 'unknown';
  let keyExchange = null;
  let cipher = null;
  let protocol = null;

  if (qInfo) {
    pqStatus = qInfo.pqStatus || 'unknown';
    keyExchange = qInfo.keyExchange;
    cipher = qInfo.cipher;
    protocol = qInfo.protocol;
  }

  if (!isHttps && isHttp) pqStatus = 'no_tls';
  if (isChromeInternal) pqStatus = 'internal';

  // Build UI
  const STATUS_MAP = {
    'pq_safe': {
      icon: svgIcon('shield'),
      class: 'quantum-safe',
      title: t('qStatusPQSafe'),
      desc: t('qDescPQSafe'),
      grade: 'Q+'
    },
    'classic': {
      icon: svgIcon('warn'),
      class: 'quantum-classic',
      title: t('qStatusClassic'),
      desc: t('qDescClassic'),
      grade: 'C'
    },
    'no_tls': {
      icon: svgIcon('x'),
      class: 'quantum-danger',
      title: t('qStatusNoTLS'),
      desc: t('qDescNoTLS'),
      grade: '!'
    },
    'unknown': {
      icon: svgIcon('help'),
      class: 'quantum-unknown',
      title: t('qStatusUnknown'),
      desc: t('qDescUnknown'),
      grade: '?'
    },
    'internal': {
      icon: svgIcon('help'),
      class: 'quantum-unknown',
      title: t('qStatusInternal'),
      desc: t('qDescInternal'),
      grade: '-'
    }
  };

  const status = STATUS_MAP[pqStatus] || STATUS_MAP['unknown'];

  let html = `
    <div class="quantum-header ${status.class}">
      <div class="quantum-icon">${status.icon}</div>
      <div class="quantum-grade">${status.grade}</div>
      <div class="quantum-title">${status.title}</div>
      <div class="quantum-desc">${status.desc}</div>
    </div>

    <div class="quantum-details">
      <div class="quantum-detail-title">${t('qDetailsTitle')}</div>

      <div class="quantum-row">
        <span class="quantum-label">${t('qProtocol')}</span>
        <span class="quantum-value">${isHttps ? 'HTTPS (TLS 1.3)' : isHttp ? 'HTTP' : isChromeInternal ? 'N/A' : protocol || '?'}</span>
      </div>

      <div class="quantum-row">
        <span class="quantum-label">${t('qKeyExchange')}</span>
        <span class="quantum-value ${keyExchange && /kyber|mlkem/i.test(keyExchange) ? 'qval-safe' : 'qval-classic'}">${keyExchange || (isHttps ? t('qDetecting') : '-')}</span>
      </div>

      <div class="quantum-row">
        <span class="quantum-label">${t('qCipher')}</span>
        <span class="quantum-value">${cipher || (isHttps ? t('qDetecting') : '-')}</span>
      </div>
    </div>

    <div class="quantum-info">
      <div class="quantum-info-title">${t('qInfoTitle')}</div>
      <div class="quantum-info-item">
        <span class="qi-icon">${svgIcon('shield')}</span>
        <div>
          <div class="qi-label">${t('qInfoPQLabel')}</div>
          <div class="qi-desc">${t('qInfoPQDesc')}</div>
        </div>
      </div>
      <div class="quantum-info-item">
        <span class="qi-icon">${svgIcon('warn')}</span>
        <div>
          <div class="qi-label">${t('qInfoClassicLabel')}</div>
          <div class="qi-desc">${t('qInfoClassicDesc')}</div>
        </div>
      </div>
      <div class="quantum-info-item">
        <span class="qi-icon">${svgIcon('clock')}</span>
        <div>
          <div class="qi-label">${t('qInfoHNDLLabel')}</div>
          <div class="qi-desc">${t('qInfoHNDLDesc')}</div>
        </div>
      </div>
    </div>`;

  quantumContent.innerHTML = html;
}

// --- Protect Tab ---
function loadProtect() {
  msgBg({ action: 'getSettings' }, (settings) => {
    if (!settings) { protectContent.innerHTML = `<div class="loading">...</div>`; return; }
    const shieldToggles = [
      { key: 'autoDeleteExpired', icon: svgIcon('clock'), labelKey: 'settAutoDelete', descKey: 'settAutoDeleteDesc', onKey: 'settAutoDeleteOn', offKey: 'settAutoDeleteOff' },
      { key: 'blockExfil', icon: svgIcon('shield'), labelKey: 'settBlockExfil', descKey: 'settBlockExfilDesc', onKey: 'settBlockExfilOn', offKey: 'settBlockExfilOff' },
    ];

    // All shield keys for master switch
    const allShieldKeys = [
      'autoDeleteExpired', 'blockExfil', 'antiPhishing', 'formSpy',
      'antiFingerprint', 'blockTrackers', 'antiMiner', 'hideCookieBanners',
      'antiWebRTC', 'antiKeylogger', 'antiTabNapping', 'clipboardGuard',
      'jsThreatScan', 'darkPatternDetect', 'breachCheck',
      'blockJavascriptUrls', 'blockDataIframes'
    ];

    const shieldFeatures = [
      { key: 'antiPhishing', icon: svgIcon('phishing'), labelKey: 'shieldPhishing', descKey: 'shieldPhishingDesc' },
      { key: 'formSpy', icon: svgIcon('form'), labelKey: 'shieldFormSpy', descKey: 'shieldFormSpyDesc' },
      { key: 'antiFingerprint', icon: svgIcon('fingerprint'), labelKey: 'shieldFingerprint', descKey: 'shieldFingerprintDesc' },
      { key: 'blockTrackers', icon: svgIcon('eye'), labelKey: 'shieldTrackers', descKey: 'shieldTrackersDesc' },
      { key: 'antiMiner', icon: svgIcon('miner'), labelKey: 'shieldMiner', descKey: 'shieldMinerDesc' },
      { key: 'hideCookieBanners', icon: svgIcon('cookie'), labelKey: 'shieldCookies', descKey: 'shieldCookiesDesc' },
      { key: 'antiWebRTC', icon: svgIcon('globe'), labelKey: 'shieldWebRTC', descKey: 'shieldWebRTCDesc' },
      { key: 'antiKeylogger', icon: svgIcon('keyboard'), labelKey: 'shieldKeylogger', descKey: 'shieldKeyloggerDesc' },
      { key: 'antiTabNapping', icon: svgIcon('link'), labelKey: 'shieldTabNapping', descKey: 'shieldTabNappingDesc' },
      { key: 'clipboardGuard', icon: svgIcon('clipboard'), labelKey: 'shieldClipboard', descKey: 'shieldClipboardDesc' },
      { key: 'jsThreatScan', icon: svgIcon('search'), labelKey: 'shieldJsThreat', descKey: 'shieldJsThreatDesc' },
      { key: 'darkPatternDetect', icon: svgIcon('alarm'), labelKey: 'shieldDarkPattern', descKey: 'shieldDarkPatternDesc' },
      { key: 'breachCheck', icon: svgIcon('unlock'), labelKey: 'shieldBreachCheck', descKey: 'shieldBreachCheckDesc' },
      { key: 'blockJavascriptUrls', icon: svgIcon('stop'), labelKey: 'shieldJsUrls', descKey: 'shieldJsUrlsDesc' },
      { key: 'blockDataIframes', icon: svgIcon('clickjack'), labelKey: 'shieldDataIframes', descKey: 'shieldDataIframesDesc' },
    ];

    // Determine master switch state
    const allOn = allShieldKeys.every(k => settings[k]);
    const allOff = allShieldKeys.every(k => !settings[k]);
    const masterChecked = allOn || (!allOff && allShieldKeys.filter(k => settings[k]).length > allShieldKeys.length / 2);

    let html = `
      <div class="master-switch-row ${masterChecked ? 'master-on' : 'master-off'}">
        <div class="master-info">
          <div class="master-label">${svgIcon('bolt')} ${t('masterSwitch')}</div>
          <div class="master-desc">${t('masterSwitchDesc')}</div>
        </div>
        <label class="toggle toggle-master">
          <input type="checkbox" id="masterToggle" ${masterChecked ? 'checked' : ''}>
          <span class="toggle-slider"></span>
        </label>
      </div>
      <div class="settings-section">`;

    // Original toggles
    for (const tog of shieldToggles) {
      html += `
        <div class="setting-row">
          <div class="setting-info">
            <div class="setting-label">${tog.icon} ${t(tog.labelKey)}</div>
            <div class="setting-desc">${t(tog.descKey)}</div>
          </div>
          <label class="toggle">
            <input type="checkbox" class="shield-toggle" data-key="${tog.key}" ${settings[tog.key] ? 'checked' : ''}>
            <span class="toggle-slider"></span>
          </label>
        </div>`;
    }

    // Shield title
    html += `</div>
      <div class="shield-section-title">${svgIcon('shield')} ${t('shieldTitle')}</div>
      <div class="settings-section">`;

    // Shield feature toggles
    for (const feat of shieldFeatures) {
      html += `
        <div class="setting-row">
          <div class="setting-info">
            <div class="setting-label">${feat.icon} ${t(feat.labelKey)}</div>
            <div class="setting-desc">${t(feat.descKey)}</div>
          </div>
          <label class="toggle">
            <input type="checkbox" class="shield-toggle" data-key="${feat.key}" ${settings[feat.key] ? 'checked' : ''}>
            <span class="toggle-slider"></span>
          </label>
        </div>`;
    }

    html += `</div>`;
    protectContent.innerHTML = html;

    // Master switch handler
    const masterToggle = document.getElementById('masterToggle');
    if (masterToggle) {
      masterToggle.addEventListener('change', () => {
        const val = masterToggle.checked;
        const newSettings = {};
        allShieldKeys.forEach(k => { newSettings[k] = val; });
        // Update all visible toggles
        protectContent.querySelectorAll('.shield-toggle').forEach(cb => {
          cb.checked = val;
        });
        // Update master row visual
        const masterRow = protectContent.querySelector('.master-switch-row');
        if (masterRow) {
          masterRow.className = 'master-switch-row ' + (val ? 'master-on' : 'master-off');
        }
        msgBg({ action: 'setSettings', settings: newSettings }, () => {
          showToast(val ? t('masterOn') : t('masterOff'));
        });
      });
    }

    // Universal toggle handler — collects all settings from checkboxes
    protectContent.querySelectorAll('.shield-toggle').forEach(input => {
      input.addEventListener('change', () => {
        const newSettings = {};
        protectContent.querySelectorAll('.shield-toggle').forEach(cb => {
          newSettings[cb.dataset.key] = cb.checked;
        });
        msgBg({ action: 'setSettings', settings: newSettings }, () => {
          const settKey = input.dataset.key;
          const togInfo = shieldToggles.find(item => item.key === settKey);
          if (togInfo) {
            showToast(input.checked ? t(togInfo.onKey) : t(togInfo.offKey));
          } else {
            showToast(input.checked ? t('stateOn') : t('stateOff'));
          }
          // Update master toggle state
          const mt = document.getElementById('masterToggle');
          if (mt) {
            const allCbs = protectContent.querySelectorAll('.shield-toggle');
            const checkedCount = [...allCbs].filter(c => c.checked).length;
            mt.checked = checkedCount > allCbs.length / 2;
            const masterRow = protectContent.querySelector('.master-switch-row');
            if (masterRow) {
              masterRow.className = 'master-switch-row ' + (mt.checked ? 'master-on' : 'master-off');
            }
          }
        });
      });
    });

    // Stats: trackers + fingerprint + shield events
    loadShieldStats();

    // Auto-delete log
    loadProtectLogs();
  });
}

function loadShieldStats() {
  const locale = currentLang === 'ru' ? 'ru-RU' : 'en-US';

  // Tracker count (read blocking state from the checkboxes already rendered)
  const blockingOn = protectContent.querySelector('.shield-toggle[data-key="blockTrackers"]');
  const isBlocking = blockingOn && blockingOn.checked;

  msgBg({ action: 'getTrackerCount', tabId: currentTabId }, (tc) => {
    const total = (tc && tc.total) || 0;
    const domains = (tc && tc.domains) ? Object.keys(tc.domains) : [];

    if (total > 0 || isBlocking) {
      const label = isBlocking && total === 0
        ? t('trackersBlocking')
        : `${t('trackersFound')} ${t('trackersFrom')} ${domains.length} ${t('trackersCompanies')}`;
      const value = isBlocking && total === 0 ? svgIcon('shield') : total;
      const statsHtml = `<div class="shield-stats">
        <div class="shield-stat">
          <span class="shield-stat-icon">${svgIcon('eye')}</span>
          <span class="shield-stat-value">${value}</span>
          <span class="shield-stat-label">${label}</span>
        </div>
      </div>`;
      protectContent.insertAdjacentHTML('beforeend', statsHtml);
    }
  });

  // Shield events (phishing, form blocks, miner blocks, fingerprint)
  msgBg({ action: 'getShieldEvents', tabId: currentTabId }, (events) => {
    if (!events || events.length === 0) return;

    const fpCount = events.filter(e => e.action === 'fingerprintDetected').length;
    let evHtml = '';

    if (fpCount > 0) {
      evHtml += `<div class="shield-stats">
        <div class="shield-stat">
          <span class="shield-stat-icon">${svgIcon('fingerprint')}</span>
          <span class="shield-stat-value">${fpCount}</span>
          <span class="shield-stat-label">${t('fpAttempts')}</span>
        </div>
      </div>`;
    }

    // Events log
    const EVENT_LABELS = {
      'phishingDetected': { icon: svgIcon('phishing'), labelKey: 'eventPhishing' },
      'formBlocked': { icon: svgIcon('form'), labelKey: 'eventFormBlock' },
      'minerBlocked': { icon: svgIcon('miner'), labelKey: 'eventMinerBlock' },
      'fingerprintDetected': { icon: svgIcon('fingerprint'), labelKey: 'eventFingerprint' },
      'cookieBannerHidden': { icon: svgIcon('cookie'), labelKey: 'eventCookieHidden' },
      'webrtcBlocked': { icon: svgIcon('globe'), labelKey: 'eventWebRTCBlock' },
      'keyloggerDetected': { icon: svgIcon('keyboard'), labelKey: 'eventKeylogger' },
      'tabNappingBlocked': { icon: svgIcon('link'), labelKey: 'eventTabNapping' },
      'clipboardSwapBlocked': { icon: svgIcon('clipboard'), labelKey: 'eventClipboardSwap' },
      'jsThreatFound': { icon: svgIcon('search'), labelKey: 'eventJsThreat' },
      'darkPatternFound': { icon: svgIcon('alarm'), labelKey: 'eventDarkPattern' },
      'breachFound': { icon: svgIcon('unlock'), labelKey: 'eventBreach' },
    };

    evHtml += `<div class="protect-log"><div class="protect-log-title">${svgIcon('log')} ${t('eventsLog')}</div>`;
    for (const ev of events.slice(-10).reverse()) {
      const info = EVENT_LABELS[ev.action] || { icon: svgIcon('help'), labelKey: ev.action };
      const time = new Date(ev.timestamp).toLocaleString(locale);
      evHtml += `<div class="protect-log-item">
        <span>${info.icon} ${t(info.labelKey)}</span>
        <span style="color:#475569">${time}</span>
      </div>`;
    }
    evHtml += '</div>';
    protectContent.insertAdjacentHTML('beforeend', evHtml);
  });
}

function loadProtectLogs() {
  const locale = currentLang === 'ru' ? 'ru-RU' : 'en-US';

  msgBg({ action: 'getAutoDeleteLog' }, (log) => {
    let logHtml = `<div class="protect-log"><div class="protect-log-title">${svgIcon('form')} ${t('logTitle')}</div>`;
    if (!log || log.length === 0) {
      logHtml += `<div class="protect-log-empty">${t('logEmpty')}</div>`;
    } else {
      for (const entry of log.slice(-10).reverse()) {
        const time = new Date(entry.timestamp).toLocaleString(locale);
        logHtml += `<div class="protect-log-item">
          <span>${escapeHtml(entry.key)} (${escapeHtml(entry.domain)})</span>
          <span style="color:#475569">${time}</span>
        </div>`;
      }
    }
    logHtml += '</div>';

    msgBg({ action: 'getExfilAlerts', tabId: currentTabId }, (alerts) => {
      const blocked = (alerts || []).filter(a => a.blocked);
      if (blocked.length > 0) {
        logHtml += `<div class="protect-log"><div class="protect-log-title">${svgIcon('stop')} ${t('logBlockedTitle')}</div>`;
        for (const a of blocked.slice(-10).reverse()) {
          logHtml += `<div class="protect-log-item">
            <span>${escapeHtml(a.method.toUpperCase())} \u2192 ${escapeHtml(a.url)}</span>
            <span class="protect-blocked-badge">${t('exfilBlocked')}</span>
          </div>`;
        }
        logHtml += '</div>';
      }
      protectContent.insertAdjacentHTML('beforeend', logHtml);
    });
  });
}

// --- Audit Tab ---
let _auditPassive = null;
let _auditActive = null;
let _auditActiveXss = null;
let _auditActiveForm = null;
let _auditUrlParams = null;
let _auditForms = null;
let _auditUrl = null;
// Survive loadAudit() re-renders (e.g. language switch) while a test runs.
let _auditRunning = false;
let _auditError = null;

function loadAudit() {
  auditContent.innerHTML = `<div class="loading">${t('auditLoading')}</div>`;

  msgTab(currentTabId, { action: 'auditPage' }, (result) => {
    if (!result) {
      auditContent.innerHTML = `
        <div class="status safe">
          <span class="status-icon">${svgIcon('lock')}</span>
          <div>
            <div class="status-text">${t('noAccess')}</div>
            <div class="status-sub">${t('noAccessSub')}</div>
          </div>
        </div>`;
      return;
    }

    _auditPassive = result.findings || [];
    _auditUrlParams = result.urlParams || [];
    _auditForms = result.pageForms || [];
    _auditUrl = result.url;
    _auditActive = null;
    _auditActiveXss = null;
    _auditActiveForm = null;

    // Get headers to cross-reference CSP
    msgBg({ action: 'getHeaderResults', tabId: currentTabId }, (hr) => {
      _auditHeaders = hr;
      renderAudit();
    });
  });
}

let _auditHeaders = null;

function renderAudit() {
  const hasCSP = _auditHeaders && _auditHeaders.found && _auditHeaders.found.includes('content-security-policy');

  // If CSP exists, adjust passive XSS findings
  const adjustedPassive = (_auditPassive || []).map(f => {
    if (f.type === 'xss' && hasCSP && f.subtype !== 'active_reflected') {
      return { ...f, severity: 'info', cspProtected: true };
    }
    return f;
  });

  // Header-based findings
  const headerFindings = [];
  if (_auditHeaders) {
    const ah = _auditHeaders.auditHeaders || {};
    const missing = _auditHeaders.missing || [];

    // CORS misconfiguration
    if (ah['access-control-allow-origin'] === '*') {
      headerFindings.push({
        type: 'cors', subtype: 'wildcard_origin', severity: 'warning',
        detail: 'CORS: Access-Control-Allow-Origin: * — any site can read responses'
      });
    }
    if (ah['access-control-allow-origin'] === '*' && ah['access-control-allow-credentials'] === 'true') {
      headerFindings.push({
        type: 'cors', subtype: 'cors_credentials', severity: 'critical',
        detail: 'CORS: wildcard origin + credentials allowed — critical misconfiguration'
      });
    }

    // Clickjacking
    if (missing.includes('x-frame-options') && !(_auditHeaders.found || []).includes('content-security-policy')) {
      headerFindings.push({
        type: 'clickjack', subtype: 'no_xfo', severity: 'warning',
        detail: 'Clickjacking: no X-Frame-Options or CSP frame-ancestors — site can be embedded in iframe'
      });
    }

    // Server info disclosure
    if (ah['server'] && ah['server'].length > 0) {
      const sv = ah['server'];
      if (/[\d.]+/.test(sv)) {
        headerFindings.push({
          type: 'info_disclosure', subtype: 'server_version', severity: 'info',
          detail: `Server header exposes version: ${sv.substring(0, 60)}`
        });
      }
    }
    if (ah['x-powered-by']) {
      headerFindings.push({
        type: 'info_disclosure', subtype: 'powered_by', severity: 'info',
        detail: `X-Powered-By: ${ah['x-powered-by'].substring(0, 60)} — technology stack exposed`
      });
    }
    if (ah['x-aspnet-version'] || ah['x-aspnetmvc-version']) {
      const ver = ah['x-aspnet-version'] || ah['x-aspnetmvc-version'];
      headerFindings.push({
        type: 'info_disclosure', subtype: 'aspnet_version', severity: 'info',
        detail: `ASP.NET version exposed: ${ver}`
      });
    }
  }

  const allFindings = [...adjustedPassive, ...(_auditActive || []), ...(_auditActiveXss || []), ...(_auditActiveForm || []), ...headerFindings];
  const xssFindings = allFindings.filter(f => f.type === 'xss');
  const sqliFindings = allFindings.filter(f => f.type === 'sqli');
  const sstiFindings = allFindings.filter(f => f.type === 'ssti');
  const pathFindings = allFindings.filter(f => f.type === 'path_traversal');
  const cmdiFindings = allFindings.filter(f => f.type === 'cmdi');
  const csrfFindings = allFindings.filter(f => f.type === 'csrf');
  const idorFindings = allFindings.filter(f => f.type === 'idor');
  const redirectFindings = allFindings.filter(f => f.type === 'redirect');
  const corsFindings = allFindings.filter(f => f.type === 'cors');
  const clickjackFindings = allFindings.filter(f => f.type === 'clickjack');
  const mixedFindings = allFindings.filter(f => f.type === 'mixed');
  const infoFindings = allFindings.filter(f => f.type === 'info_disclosure');
  const critCount = allFindings.filter(f => f.severity === 'critical').length;
  const warnCount = allFindings.filter(f => f.severity === 'warning').length;
  const infoCount = allFindings.filter(f => f.severity === 'info').length;

  const statusClass = critCount > 0 ? 'danger' : warnCount > 0 ? 'warning' : 'safe';
  const statusIcon = critCount > 0 ? svgIcon('warn') : warnCount > 0 ? svgIcon('warn') : svgIcon('ok');
  const statusText = allFindings.length === 0 ? t('auditClean') : `${t('found')}: ${allFindings.length}`;
  const statusSub = allFindings.length === 0
    ? t('auditCleanSub')
    : `${critCount} ${t('critical')}, ${warnCount} ${t('warnings')}, ${infoCount} ${t('auditInfo')}`;

  let html = `
    <div class="status ${statusClass}">
      <span class="status-icon">${statusIcon}</span>
      <div>
        <div class="status-text">${statusText}</div>
        <div class="status-sub">${statusSub}</div>
      </div>
    </div>`;

  // Vulnerability descriptions by subtype
  const vulnDesc = currentLang === 'ru' ? {
    // XSS
    reflected_param: 'Параметр из URL отражается в HTML без фильтрации. Злоумышленник может подставить скрипт в ссылку и украсть данные пользователя.',
    javascript_uri: 'Ссылка с javascript: протоколом выполняет произвольный код при клике. Может использоваться для кражи куки или перенаправления.',
    inline_handlers: 'Inline-обработчики событий (onclick, onerror) могут стать точкой входа для XSS если в них попадают пользовательские данные.',
    data_uri: 'Фрейм с data: URI может содержать фишинговую форму или вредоносный скрипт, обходя политику безопасности.',
    dom_sink: 'Опасная JS-функция (innerHTML, eval, document.write) найдена в коде. Если в неё попадают непроверенные данные — возможен XSS.',
    dom_source_sink: 'Данные из URL попадают в опасные функции (innerHTML, eval, document.write) без проверки — классический DOM XSS.',
    active_reflected: 'Отправленный payload отразился в ответе без экранирования. Подтверждённая XSS-уязвимость — можно выполнить произвольный JavaScript.',
    active_form_reflected: 'Payload из формы отразился в ответе. Подтверждённая Stored/Reflected XSS через POST-запрос.',
    // SQLi
    error_message: 'Страница содержит ошибку SQL-движка. Вероятно, пользовательский ввод попадает в SQL-запрос без параметризации.',
    active_error: 'Payload вызвал ошибку SQL. Подтверждённая SQL-инъекция — атакующий может читать/изменять базу данных.',
    active_blind: 'Сервер задержал ответ на SQL SLEEP() — подтверждённая blind SQL-инъекция. Данные можно извлекать посимвольно.',
    active_nosql: 'MongoDB-оператор вызвал ошибку. Подтверждённая NoSQL-инъекция — можно обойти авторизацию или извлечь данные.',
    active_form_error: 'SQL-ошибка через форму. Подтверждённая инъекция — данные из формы попадают в SQL напрямую.',
    active_form_nosql: 'NoSQL-ошибка через форму. Подтверждённая инъекция — MongoDB-операторы выполняются из поля формы.',
    // SSTI
    active_ssti: 'Шаблонизатор выполнил математику из ввода. Подтверждённая SSTI — можно выполнить произвольный код на сервере.',
    active_form_ssti: 'SSTI через форму. Шаблонизатор выполнил вычисление — полный контроль над сервером через инъекцию шаблона.',
    // Path Traversal
    active_path: 'Содержимое системного файла попало в ответ. Подтверждённый Path Traversal — можно читать любые файлы на сервере.',
    active_form_path: 'Path Traversal через форму. Системный файл прочитан — атакующий может получить пароли, конфиги, исходный код.',
    // CMDi
    active_cmdi: 'Сервер выполнил системную команду из ввода. Подтверждённая OS Command Injection — полный контроль над сервером.',
    active_form_cmdi: 'Command Injection через форму. Команда выполнена — атакующий может выполнять любые команды на сервере.',
    // CSRF
    no_csrf_token: 'Форма без CSRF-токена — вредоносный сайт может отправить запрос от имени пользователя (перевод денег, смена пароля).',
    no_csrf_meta: 'Фреймворк не использует мета-тег для CSRF-защиты. SPA-приложение может быть уязвимо к подделке запросов.',
    session_cookies: 'Сессионные куки без SameSite — браузер отправит их с запросом с чужого сайта, что позволяет CSRF-атаку.',
    // IDOR
    path_id: 'Числовой ID в пути URL можно подменить. Если сервер не проверяет права доступа, можно получить чужие данные.',
    param_id: 'Числовой ID в параметре URL можно подменить. Если сервер не проверяет права — доступ к чужим данным.',
    api_call: 'API-запрос с числовым ID. Если авторизация не проверяется — можно получить данные других пользователей.',
    // Redirect
    open_redirect: 'Параметр URL ведёт на внешний домен. Злоумышленник может подставить ссылку на фишинговый сайт.',
    // CORS
    cors_credentials: 'CORS с credentials разрешён для стороннего домена — чужой сайт может читать приватные данные API от имени пользователя.',
    cors_wildcard: 'Access-Control-Allow-Origin: * — любой сайт может читать ответы API, включая персональные данные.',
    // Clickjacking
    no_xfo: 'Сайт можно встроить в невидимый фрейм. Пользователь кликает по скрытым кнопкам, не подозревая об этом.',
    // Mixed Content
    mixed_content: 'Ресурс загружается по HTTP на HTTPS-странице. Скрипт или стиль можно подменить при MITM-атаке и выполнить произвольный код.',
    // Info Disclosure
    server_version: 'Версия сервера раскрыта — атакующий может искать известные уязвимости (CVE) для этой версии.',
    powered_by: 'Технологический стек раскрыт — упрощает подбор эксплоитов под конкретную версию.',
    aspnet_version: 'Версия ASP.NET раскрыта — атакующий может использовать известные уязвимости этой версии.',
    html_comments: 'Чувствительные данные в HTML-комментариях — пароли, пути, TODO-заметки видны в исходном коде страницы.',
  } : {
    reflected_param: 'URL parameter is reflected in HTML without filtering. Attacker can inject script via crafted link and steal user data.',
    javascript_uri: 'Link with javascript: protocol executes arbitrary code on click. Can steal cookies or redirect users.',
    inline_handlers: 'Inline event handlers (onclick, onerror) can become XSS entry points if they process user-controlled data.',
    data_uri: 'Frame with data: URI can contain phishing forms or malicious scripts, bypassing security policies.',
    dom_sink: 'Dangerous JS function (innerHTML, eval, document.write) found in code. If it processes unchecked data — XSS is possible.',
    dom_source_sink: 'Data from URL flows into dangerous functions (innerHTML, eval, document.write) without validation — classic DOM XSS.',
    active_reflected: 'Payload was reflected in response without encoding. Confirmed XSS — arbitrary JavaScript can be executed.',
    active_form_reflected: 'Form payload reflected in response. Confirmed Stored/Reflected XSS via POST request.',
    error_message: 'Page contains SQL engine error. User input likely goes into SQL query without parameterization.',
    active_error: 'Payload triggered SQL error. Confirmed SQL injection — attacker can read/modify the database.',
    active_blind: 'Server delayed response to SQL SLEEP() — confirmed blind SQL injection. Data can be extracted character by character.',
    active_nosql: 'MongoDB operator triggered error. Confirmed NoSQL injection — can bypass auth or extract data.',
    active_form_error: 'SQL error via form. Confirmed injection — form data goes directly into SQL queries.',
    active_form_nosql: 'NoSQL error via form. Confirmed injection — MongoDB operators execute from form fields.',
    active_ssti: 'Template engine executed math from input. Confirmed SSTI — arbitrary code execution on server.',
    active_form_ssti: 'SSTI via form. Template engine executed computation — full server control via template injection.',
    active_path: 'System file content appeared in response. Confirmed Path Traversal — any file on server can be read.',
    active_form_path: 'Path Traversal via form. System file read — attacker can access passwords, configs, source code.',
    active_cmdi: 'Server executed system command from input. Confirmed OS Command Injection — full server control.',
    active_form_cmdi: 'Command Injection via form. Command executed — attacker can run any command on the server.',
    no_csrf_token: 'Form without CSRF token — malicious site can submit requests on behalf of the user (transfer money, change password).',
    no_csrf_meta: 'Framework does not use CSRF meta tag. SPA application may be vulnerable to request forgery.',
    session_cookies: 'Session cookies without SameSite — browser sends them with cross-site requests, enabling CSRF attacks.',
    path_id: 'Numeric ID in URL path can be changed. If server doesn\'t check permissions, attacker can access other users\' data.',
    param_id: 'Numeric ID in URL parameter can be changed. If no authorization check — access to other users\' data.',
    api_call: 'API call with numeric ID. If authorization isn\'t verified — other users\' data can be accessed.',
    open_redirect: 'URL parameter points to external domain. Attacker can craft link to phishing site.',
    cors_credentials: 'CORS with credentials allowed for third-party domain — foreign site can read private API data on behalf of the user.',
    cors_wildcard: 'Access-Control-Allow-Origin: * — any website can read API responses, including personal data.',
    no_xfo: 'Site can be embedded in invisible frame. User clicks hidden buttons without knowing.',
    mixed_content: 'Resource loaded over HTTP on HTTPS page. Scripts or styles can be replaced in MITM attack to execute arbitrary code.',
    server_version: 'Server version exposed — attacker can search for known vulnerabilities (CVEs) for this version.',
    powered_by: 'Technology stack exposed — makes it easier to find exploits for specific version.',
    aspnet_version: 'ASP.NET version exposed — attacker can use known vulnerabilities for this version.',
    html_comments: 'Sensitive data in HTML comments — passwords, paths, TODO notes visible in page source.',
  };

  // Generic section renderer
  function renderSection(icon, title, items) {
    if (items.length === 0) return '';
    let s = `<div class="audit-section">
      <div class="audit-section-title">${icon} ${title} (${items.length})</div>`;
    for (const f of items) {
      const sevClass = f.severity === 'critical' ? 'audit-critical' : f.severity === 'warning' ? 'audit-warning' : 'audit-info';
      const desc = vulnDesc[f.subtype] || '';
      s += `<div class="audit-item ${sevClass}">
        <div class="audit-item-detail">${escapeHtml(f.detail)}</div>`;
      if (desc) s += `<div class="audit-item-desc">${desc}</div>`;
      if (f.cspProtected) s += `<div class="audit-csp-badge">${t('auditCspProtected')}</div>`;
      if (f.param) s += `<div class="audit-item-meta">${t('auditParam')}: <code>${escapeHtml(f.param)}</code></div>`;
      if (f.db) s += `<div class="audit-item-meta">DB: ${escapeHtml(f.db)}</div>`;
      if (f.payload) s += `<div class="audit-item-meta">Payload: <code>${escapeHtml(f.payload)}</code></div>`;
      if (f.id) s += `<div class="audit-item-meta">ID: <code>${escapeHtml(f.id)}</code></div>`;
      if (f.url) s += `<div class="audit-item-meta">${escapeHtml(f.url)}</div>`;
      s += '</div>';
    }
    s += '</div>';
    return s;
  }

  html += renderSection(svgIcon('xss'), 'XSS', xssFindings);
  html += renderSection(svgIcon('lock'), 'SQL Injection', sqliFindings);
  html += renderSection(svgIcon('ssti'), 'SSTI', sstiFindings);
  html += renderSection(svgIcon('path'), 'Path Traversal', pathFindings);
  html += renderSection(svgIcon('cmdi'), 'Command Injection', cmdiFindings);
  html += renderSection(svgIcon('csrf'), 'CSRF', csrfFindings);
  html += renderSection(svgIcon('idor'), 'IDOR', idorFindings);
  html += renderSection(svgIcon('redirect'), 'Open Redirect', redirectFindings);
  html += renderSection(svgIcon('globe'), 'CORS', corsFindings);
  html += renderSection(svgIcon('clickjack'), 'Clickjacking', clickjackFindings);
  html += renderSection(svgIcon('unlock'), 'Mixed Content', mixedFindings);
  html += renderSection(svgIcon('infodisc'), 'Info Disclosure', infoFindings);

  // What we check — info block
  html += `
    <div class="audit-info">
      <div class="audit-info-title">${t('auditWhatTitle')}</div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('xss')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckXssLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckXssDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('lock')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckSqliLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckSqliDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('ssti')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckSstiLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckSstiDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('path')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckPathLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckPathDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('cmdi')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckCmdiLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckCmdiDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('form')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckFormsLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckFormsDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('settings')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckSinksLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckSinksDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('csrf')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckCsrfLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckCsrfDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('idor')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckIdorLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckIdorDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('redirect')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckRedirectLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckRedirectDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('globe')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckCorsLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckCorsDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('clickjack')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckClickjackLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckClickjackDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('unlock')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckMixedLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckMixedDesc')}</div>
        </div>
      </div>
      <div class="audit-info-item">
        <span class="audit-info-icon">${svgIcon('infodisc')}</span>
        <div>
          <div class="audit-info-label">${t('auditCheckInfoLabel')}</div>
          <div class="audit-info-desc">${t('auditCheckInfoDesc')}</div>
        </div>
      </div>
    </div>`;

  // Active test button (SQLi + XSS + Forms combined)
  const activeDone = _auditActive || _auditActiveXss || _auditActiveForm;
  const hasParams = _auditUrlParams && _auditUrlParams.length > 0;
  // Only GET forms are tested (background enforces the same rule)
  const testableForms = (_auditForms || []).filter(f => f.method === 'GET');
  const hasForms = testableForms.length > 0;
  if (_auditRunning) {
    html += `
      <div class="audit-action">
        <button class="audit-btn" disabled>${svgIcon('search')} ${t('auditTesting')}</button>
      </div>`;
  } else if ((hasParams || hasForms) && !activeDone) {
    const targets = [];
    if (hasParams) targets.push(`${_auditUrlParams.length} URL`);
    if (hasForms) targets.push(`${testableForms.length} ${t('auditForms')}`);
    let host = '';
    try { host = new URL(_auditUrl).host; } catch {}
    html += `
      <div class="audit-action">
        <button class="audit-btn" id="btnActiveTest">${svgIcon('search')} ${t('auditActiveTest')}</button>
        <div class="audit-action-desc">${t('auditActiveTestDesc')} (${targets.join(' + ')})</div>
        <div class="audit-confirm" id="auditConfirm" hidden>
          <div class="audit-note">${svgIcon('warn')} ${escapeHtml(t('auditConfirm').replace('{host}', host))}</div>
          <button class="audit-btn" id="btnActiveConfirm">${t('auditConfirmRun')}</button>
          <button class="audit-btn" id="btnActiveCancel">${t('auditConfirmCancel')}</button>
        </div>
      </div>`;
  } else if (!hasParams && !hasForms && !activeDone) {
    html += `<div class="audit-note">${t('auditNoParams')}</div>`;
  }
  if (_auditError) {
    html += `<div class="audit-note" style="color:#e74c3c;">${svgIcon('warn')} ${t('auditActiveError')}: ${escapeHtml(_auditError)}</div>`;
  }
  if (activeDone) {
    const activeFindings = [...(_auditActive || []), ...(_auditActiveXss || []), ...(_auditActiveForm || [])];
    const activeVulnCount = activeFindings.length;
    if (activeVulnCount > 0) {
      html += `<div class="audit-note audit-done" style="color:#e74c3c;">${svgIcon('warn')} ${t('auditActiveDone')} — ${t('auditActiveFound')}: <b>${activeVulnCount}</b></div>`;
    } else {
      html += `<div class="audit-note audit-done">${svgIcon('ok')} ${t('auditActiveDone')} — ${t('auditActiveFound')}: 0</div>`;
    }
  }

  auditContent.innerHTML = html;

  // Active test: first click asks for confirmation naming the target host
  const btn = document.getElementById('btnActiveTest');
  if (btn) {
    const confirmBox = document.getElementById('auditConfirm');
    btn.addEventListener('click', () => {
      btn.hidden = true;
      confirmBox.hidden = false;
    });
    document.getElementById('btnActiveCancel').addEventListener('click', () => {
      btn.hidden = false;
      confirmBox.hidden = true;
    });
    document.getElementById('btnActiveConfirm').addEventListener('click', () => {
      if (_auditRunning) return;
      _auditRunning = true;
      _auditError = null;
      renderAudit();
      msgBg({
        action: 'startActiveAll',
        url: _auditUrl,
        params: _auditUrlParams,
        forms: _auditForms,
        tabId: currentTabId
      }, (results) => {
        _auditRunning = false;
        if (!results || results.error) {
          _auditError = (results && results.error) || 'no response';
        } else {
          _auditActive = results.sqli || [];
          _auditActiveXss = results.xss || [];
          _auditActiveForm = results.formResults || [];
        }
        renderAudit();
      });
    });
  }
}

// --- Init ---
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (!tabs[0]) {
    scannerContent.innerHTML = '<div class="loading">...</div>';
    return;
  }

  currentTabId = tabs[0].id;
  siteUrl.textContent = tabs[0].url || '...';

  // Load language preference then render
  chrome.storage.local.get({ lang: 'ru' }, (data) => {
    currentLang = data.lang || 'ru';
    updateUI();
  });
});
