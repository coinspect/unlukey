import { sha256 } from '@noble/hashes/sha2';

export const DEFAULT_BASE_URL = 'https://storage.googleapis.com/unlukey-datasets';

export const DATASET_CONFIG = {
  16: { bits: 128, prefixBits: 20, keepBytes: 30 },
  32: { bits: 256, prefixBits: 19, keepBytes: 30 },
};

export function bucketPrefix(key, prefixBits) {
  let v = 0, got = 0, i = 0;
  while (got < prefixBits) {
    const take = Math.min(prefixBits - got, 8);
    v = (v << take) | (key[i] >> (8 - take));
    got += take; i += 1;
  }
  return v >>> 0;
}

export function locate(entropy) {
  const config = DATASET_CONFIG[entropy.length];
  if (!config) {
    throw new RangeError(`entropy must be 16 or 32 bytes, got ${entropy.length}`);
  }
  const { bits, prefixBits, keepBytes } = config;
  const pfxBytes = Math.floor(prefixBits / 8);
  const hexWidth = Math.ceil(prefixBits / 4);

  const key = sha256(entropy);
  const prefix = bucketPrefix(key, prefixBits);
  const prefixHex = prefix.toString(16).padStart(hexWidth, '0');
  const suffix = key.subarray(pfxBytes, pfxBytes + keepBytes);

  return { bits, keepBytes, key, prefix, prefixHex, suffix };
}

export function matchSuffix(bucketBytes, suffix, keepBytes) {
  for (let i = 0; i + keepBytes <= bucketBytes.length; i += keepBytes) {
    let eq = true;
    for (let j = 0; j < keepBytes; j++) {
      if (bucketBytes[i + j] !== suffix[j]) { eq = false; break; }
    }
    if (eq) return true;
  }
  return false;
}

export async function checkWith(entropy, readBucket) {
  const { bits, keepBytes, key, prefixHex, suffix } = locate(entropy);
  const { bucketPath, bucket } = await readBucket(bits, prefixHex);
  if (bucket == null) {
    return { vulnerable: false, key, prefix: prefixHex, bucketPath, reason: 'no bucket for this prefix' };
  }
  return matchSuffix(bucket, suffix, keepBytes)
    ? { vulnerable: true, key, prefix: prefixHex, bucketPath }
    : { vulnerable: false, key, prefix: prefixHex, bucketPath, reason: 'no match in the dataset' };
}

export async function check(entropy, baseUrl = DEFAULT_BASE_URL) {
  return checkWith(entropy, async (bits, prefixHex) => {
    const bucketPath = `${baseUrl.replace(/\/+$/, '')}/${bits}/${prefixHex}`;
    const res = await fetch(bucketPath);
    if (res.status === 404) return { bucketPath, bucket: null };
    if (!res.ok) throw new Error(`fetch ${bucketPath} failed: ${res.status} ${res.statusText}`);
    return { bucketPath, bucket: new Uint8Array(await res.arrayBuffer()) };
  });
}
