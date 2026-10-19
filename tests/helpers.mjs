import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

export function readManifest() {
  return JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
}

// Every file the extension needs at runtime: manifest references, the
// service worker's importScripts(), and every top-level extension page
// (popup, warning page) with whatever it pulls in via <script src> / <link href>.
export function extensionFiles() {
  const m = readManifest();
  const files = new Set(['manifest.json']);
  const sw = m.background?.service_worker;
  if (sw) {
    files.add(sw);
    const src = readFileSync(join(ROOT, sw), 'utf8');
    for (const [, ref] of src.matchAll(/importScripts\(\s*'([^']+)'/g)) files.add(ref);
  }
  for (const icon of Object.values({ ...m.icons, ...m.action?.default_icon })) files.add(icon);
  for (const cs of m.content_scripts ?? []) {
    for (const f of [...(cs.js ?? []), ...(cs.css ?? [])]) files.add(f);
  }
  for (const page of readdirSync(ROOT).filter((f) => f.endsWith('.html'))) {
    files.add(page);
    const html = readFileSync(join(ROOT, page), 'utf8');
    for (const [, ref] of html.matchAll(/(?:src|href)="([^"#:]+)"/g)) files.add(ref);
  }
  return [...files];
}
