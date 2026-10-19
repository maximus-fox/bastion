import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, readManifest, extensionFiles } from './helpers.mjs';

test('manifest is MV3 with name and version', () => {
  const m = readManifest();
  assert.equal(m.manifest_version, 3);
  assert.ok(m.name);
  assert.match(m.version, /^\d+(\.\d+){0,3}$/);
});

test('every referenced file exists', () => {
  const missing = extensionFiles().filter((f) => !existsSync(join(ROOT, f)));
  assert.deepEqual(missing, []);
});

test('package.json version matches manifest version', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const norm = (v) => v.split('.').concat(['0', '0']).slice(0, 3).join('.');
  assert.equal(norm(pkg.version), norm(readManifest().version));
});
