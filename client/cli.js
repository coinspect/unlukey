import { readFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { checkWith, DEFAULT_BASE_URL } from './index.js';

const DEFAULT_DATASETS_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'datasets');

function hexToEntropy(hex) {
  if (!/^[0-9a-fA-F]+$/.test(hex) || (hex.length !== 32 && hex.length !== 64)) {
    throw new RangeError('entropy must be 32 hex chars (12-word) or 64 hex chars (24-word)');
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

async function main() {
  const args = process.argv.slice(2);
  const remoteIdx = args.indexOf('--remote');
  if (remoteIdx !== -1) args.splice(remoteIdx, 1);
  const remote = remoteIdx !== -1;
  const [input, location] = args;
  if (!input) {
    console.error('usage: cli.js <hex-entropy> [datasets-root]');
    console.error('       cli.js --remote <hex-entropy> [baseUrl]');
    process.exit(2);
  }
  const entropy = hexToEntropy(input);
  const result = remote
    ? await checkWith(entropy, async (bits, prefixHex) => {
        const bucketPath = `${(location || DEFAULT_BASE_URL).replace(/\/+$/, '')}/${bits}/${prefixHex}`;
        const res = await fetch(bucketPath);
        if (res.status === 404) return { bucketPath, bucket: null };
        if (!res.ok) throw new Error(`fetch ${bucketPath} failed: ${res.status} ${res.statusText}`);
        return { bucketPath, bucket: new Uint8Array(await res.arrayBuffer()) };
      })
    : await checkWith(entropy, async (bits, prefixHex) => {
        const bucketPath = path.join(location || DEFAULT_DATASETS_ROOT, String(bits), prefixHex);
        try {
          return { bucketPath, bucket: await readFile(bucketPath) };
        } catch (err) {
          if (err.code === 'ENOENT') return { bucketPath, bucket: null };
          throw err;
        }
      });
  console.error(`key = ${Buffer.from(result.key).toString('hex')} (prefix ${result.prefix}, bucket ${result.bucketPath})`);
  console.log(result.vulnerable
    ? 'VULNERABLE: this entropy matches a known weak-seed candidate'
    : `not found: ${result.reason}`);
  process.exit(result.vulnerable ? 1 : 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
