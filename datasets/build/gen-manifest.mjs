#!/usr/bin/env node
// Assembles datasets/manifest.json from client/index.js's DATASET_CONFIG, datasets/.counts/, and
// each vulnerabilities/<dir>/meta.json. Run after building/updating any tree.
import { readFileSync, writeFileSync, readdirSync, existsSync, statSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { DATASET_CONFIG } from '../../client/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..');
const VULN_DIR = path.join(REPO, 'vulnerabilities');
const COUNTS_DIR = path.join(REPO, 'datasets', '.counts');
const OUT = path.join(REPO, 'datasets', 'manifest.json');

// editorial metadata, keyed by vuln id, from each vulnerabilities/<dir>/meta.json
const meta = {};
for (const dir of readdirSync(VULN_DIR)) {
  const metaPath = path.join(VULN_DIR, dir, 'meta.json');
  if (existsSync(metaPath)) {
    const m = JSON.parse(readFileSync(metaPath, 'utf8'));
    meta[m.id] = m;
  }
}

// built vulnerabilities + counts, from datasets/.counts/<id>-<width>.count
const built = []; // { id, width, count }
if (existsSync(COUNTS_DIR)) {
  for (const f of readdirSync(COUNTS_DIR)) {
    const m = f.match(/^(.*)-(\d+)\.count$/u);
    if (!m) continue;
    built.push({ id: m[1], width: Number(m[2]), count: Number(readFileSync(path.join(COUNTS_DIR, f), 'utf8').trim()) });
  }
}

// one tree per entropy length present in DATASET_CONFIG; vulnerabilities filled from what's built.
const trees = {};
for (const cfg of Object.values(DATASET_CONFIG)) {
  const width = cfg.bits;
  trees[width] = {
    hashPrefixBits: cfg.prefixBits,
    bytesPerEntry: cfg.keepBytes,
    vulnerabilities: built
      .filter((b) => b.width === width)
      .map((b) => {
        const m = meta[b.id];
        if (!m) throw new Error(`count for "${b.id}" but no vulnerabilities/*/meta.json with that id`);
        return { id: m.id, name: m.name, count: b.count, references: m.references };
      })
      .sort((a, b) => a.id.localeCompare(b.id)),
  };
}

const manifest = { updated: new Date().toISOString().slice(0, 10), trees };
writeFileSync(OUT, `${JSON.stringify(manifest, null, 2)}\n`);
console.error(`[gen-manifest] wrote ${OUT}`);
for (const [w, t] of Object.entries(trees)) {
  console.error(`  ${w}: ${t.vulnerabilities.length} vuln(s) [${t.vulnerabilities.map((v) => `${v.id}=${v.count}`).join(', ') || 'none built'}]`);
}
