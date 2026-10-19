import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

export function readManifest() {
  return JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
}

// Every file the extension needs at runtime: manifest references plus
// whatever popup.html pulls in via <script src> / <link href>.
export function extensionFiles() {
  const m = readManifest();
  const files = new Set(['manifest.json']);
  if (m.background?.service_worker) files.add(m.background.service_worker);
  if (m.action?.default_popup) files.add(m.action.default_popup);
  for (const icon of Object.values({ ...m.icons, ...m.action?.default_icon })) files.add(icon);
  for (const cs of m.content_scripts ?? []) {
    for (const f of [...(cs.js ?? []), ...(cs.css ?? [])]) files.add(f);
  }
  if (m.action?.default_popup) {
    const html = readFileSync(join(ROOT, m.action.default_popup), 'utf8');
    for (const [, ref] of html.matchAll(/(?:src|href)="([^"#:]+)"/g)) files.add(ref);
  }
  return [...files];
}
