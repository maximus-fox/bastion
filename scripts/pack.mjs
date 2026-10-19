// Builds the Chrome Web Store zip from the files the extension actually uses,
// so dev tooling (node_modules, tests, configs) never ends up in the upload.
import { execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { ROOT, readManifest, extensionFiles } from '../tests/helpers.mjs';

const out = `bastion-${readManifest().version}.zip`;
rmSync(`${ROOT}/${out}`, { force: true });
execFileSync('zip', ['-q', '-X', out, ...extensionFiles()], { cwd: ROOT, stdio: 'inherit' });
console.log(`Packed ${out}`);
