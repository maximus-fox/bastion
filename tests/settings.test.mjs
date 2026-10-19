import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT } from './helpers.mjs';
import { launchExtension } from './harness.mjs';

let ext;
before(async () => { ext = await launchExtension(); });
after(() => ext?.close());

const migrate = (stored, details) => ext.sw(async ({ stored, details }) => {
  await chrome.storage.local.clear();
  await chrome.storage.local.set(stored);
  await migrateSettings(details);
  return chrome.storage.local.get(null);
}, { stored, details });

test('update keeps user choices and fills in new keys', async () => {
  const s = await migrate({ antiPhishing: false, blockTrackers: false, _version: '2.3' },
    { reason: 'update', previousVersion: '2.3' });
  assert.equal(s.antiPhishing, false);
  assert.equal(s.blockTrackers, false);
  assert.equal(s.antiFingerprint, true);
  assert.equal(s._version, JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8')).version);
});

test('update from 2.2 resets only settings whose default changed', async () => {
  const s = await migrate({ antiPhishing: false, autoDeleteExpired: true, blockJavascriptUrls: true },
    { reason: 'update', previousVersion: '2.2' });
  assert.equal(s.antiPhishing, false);
  assert.equal(s.autoDeleteExpired, false);
  assert.equal(s.blockJavascriptUrls, false);
});

test('later updates keep an opted-in setting', async () => {
  const s = await migrate({ blockJavascriptUrls: true }, { reason: 'update', previousVersion: '2.3' });
  assert.equal(s.blockJavascriptUrls, true);
});

test('injected.js fallback matches the shared defaults', () => {
  const src = (f) => readFileSync(join(ROOT, f), 'utf8');
  const defaults = new Function(`${src('defaults.js')}; return DEFAULT_SETTINGS;`)();
  const block = src('injected.js').match(/let settings = (\{[\s\S]*?\});/)[1];
  const fallback = new Function(`return ${block}`)();
  for (const [k, v] of Object.entries(fallback)) assert.equal(v, defaults[k], k);
});
