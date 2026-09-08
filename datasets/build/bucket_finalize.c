#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/resource.h>

static void mkdir_p(const char *path){
  char buf[1024]; snprintf(buf, sizeof(buf), "%s", path);
  for(char *p = buf + 1; *p; p++){
    if(*p == '/'){ *p = 0; mkdir(buf, 0755); *p = '/'; }
  }
  mkdir(buf, 0755);
}

// MSB-first -- must match bucket_partition's packing.
static uint32_t prefix_of(const uint8_t *h, int bits){
  uint32_t v = 0; int got = 0, i = 0;
  while(got < bits){
    int take = bits - got; if(take > 8) take = 8;
    v = (v << take) | (uint32_t)(h[i] >> (8 - take));
    got += take; i++;
  }
  return v;
}

static int cmp32(const void *a, const void *b){ return memcmp(a, b, 32); }

static int finalize_shard_dedup(const char *path, const char *outdir, int prefix_bits,
                                int pfx_bytes, int keep_bytes, int hexw,
                                uint64_t *total_in, uint64_t *total_uniq, uint64_t *total_files){
  struct stat st;
  if(stat(path, &st) != 0) { perror(path); return 1; }
  size_t n = (size_t)st.st_size / 32;
  if(n == 0) return 0;
  uint8_t (*keys)[32] = malloc(n * 32);
  if(!keys){ fprintf(stderr, "OOM loading shard %s (%zu keys)\n", path, n); return 1; }
  FILE *f = fopen(path, "rb");
  if(!f){ perror(path); free(keys); return 1; }
  if(fread(keys, 32, n, f) != n){ fprintf(stderr, "short read on %s\n", path); fclose(f); free(keys); return 1; }
  fclose(f);
  *total_in += n;

  qsort(keys, n, 32, cmp32);
  size_t uniq = 0;                                   // dedup in place on the full 32-byte key
  for(size_t i = 0; i < n; i++)
    if(i == 0 || memcmp(keys[i], keys[uniq-1], 32) != 0) memcpy(keys[uniq++], keys[i], 32);
  *total_uniq += uniq;

  size_t i = 0;                                       // sorted -> each prefix's keys are contiguous
  while(i < uniq){
    uint32_t p = prefix_of(keys[i], prefix_bits);
    char outpath[1024];
    snprintf(outpath, sizeof(outpath), "%s/%0*x", outdir, hexw, p);
    FILE *out = fopen(outpath, "wb");
    if(!out){ perror(outpath); free(keys); return 1; }
    size_t j = i;
    for(; j < uniq && prefix_of(keys[j], prefix_bits) == p; j++)
      fwrite(keys[j] + pfx_bytes, 1, keep_bytes, out);
    fclose(out);
    (*total_files)++;
    i = j;
  }
  free(keys);
  return 0;
}

int main(int argc, char **argv){
  const char *pos[4]; int npos = 0, dedup = 0;
  for(int i = 1; i < argc; i++){
    if(!strcmp(argv[i], "--dedup")) dedup = 1;
    else if(npos < 4) pos[npos++] = argv[i];
  }
  if(npos < 2 || npos > 4){
    fprintf(stderr, "usage: %s <shard-dir> <outdir> [prefix-bits] [keep-bytes] [--dedup]\n", argv[0]);
    return 2;
  }
  const char *shard_dir = pos[0], *outdir = pos[1];
  int prefix_bits = (npos >= 3) ? atoi(pos[2]) : 20;
  if(prefix_bits < 1 || prefix_bits > 24){ fprintf(stderr, "prefix-bits must be 1..24\n"); return 2; }
  int pfx_bytes = prefix_bits / 8;
  int keep_bytes = (npos == 4) ? atoi(pos[3]) : (32 - pfx_bytes);
  if(keep_bytes < 1 || pfx_bytes + keep_bytes > 32){
    fprintf(stderr, "keep-bytes must be 1..%d\n", 32 - pfx_bytes); return 2;
  }
  int hexw = (prefix_bits + 3) / 4;
  uint64_t nprefix = 1ull << prefix_bits;
  mkdir_p(outdir);

  DIR *d = opendir(shard_dir);
  if(!d){ perror(shard_dir); return 1; }
  uint64_t total_in = 0, total_uniq = 0, total_files = 0;
  struct dirent *e;

  if(dedup){
    while((e = readdir(d))){
      if(e->d_name[0] == '.') continue;
      char path[1200];
      snprintf(path, sizeof(path), "%s/%s", shard_dir, e->d_name);
      struct stat st;
      if(stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
      if(finalize_shard_dedup(path, outdir, prefix_bits, pfx_bytes, keep_bytes, hexw,
                              &total_in, &total_uniq, &total_files) != 0){ closedir(d); return 1; }
    }
    closedir(d);
    fprintf(stderr, "[bucket_finalize] %llu keys -> %llu unique -> %llu bucket files in %s/ (dedup)\n",
      (unsigned long long)total_in, (unsigned long long)total_uniq, (unsigned long long)total_files, outdir);
    return 0;
  }

  struct rlimit rl;
  if(getrlimit(RLIMIT_NOFILE, &rl) == 0){
    rlim_t want = 100000;
    if(rl.rlim_cur < want){
      rl.rlim_cur = (rl.rlim_max != RLIM_INFINITY && rl.rlim_max < want) ? rl.rlim_max : want;
      setrlimit(RLIMIT_NOFILE, &rl);
    }
  }
  FILE **buckets = calloc(nprefix, sizeof(FILE*));      // indexed by prefix, NULL = not open
  uint32_t *opened = NULL; size_t nopened = 0, opened_cap = 0;   // prefixes opened for current shard
  if(!buckets){ fprintf(stderr, "OOM allocating %llu bucket slots\n", (unsigned long long)nprefix); return 1; }
  const size_t BUFKEYS = 1u << 20;
  uint8_t *rbuf = malloc(BUFKEYS * 32);
  if(!rbuf){ fprintf(stderr, "OOM read buffer\n"); return 1; }

  while((e = readdir(d))){
    if(e->d_name[0] == '.') continue;
    char path[1200];
    snprintf(path, sizeof(path), "%s/%s", shard_dir, e->d_name);
    struct stat st;
    if(stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;

    FILE *f = fopen(path, "rb");
    if(!f){ perror(path); continue; }
    size_t got;
    while((got = fread(rbuf, 32, BUFKEYS, f)) > 0){
      for(size_t k = 0; k < got; k++){
        const uint8_t *key = rbuf + k * 32;
        uint32_t p = prefix_of(key, prefix_bits);
        if(!buckets[p]){
          char outpath[1024];
          snprintf(outpath, sizeof(outpath), "%s/%0*x", outdir, hexw, p);
          buckets[p] = fopen(outpath, "wb");
          if(!buckets[p]){ perror(outpath); return 1; }
          if(nopened == opened_cap){ opened_cap = opened_cap ? opened_cap*2 : 4096; opened = realloc(opened, opened_cap*sizeof(uint32_t)); }
          opened[nopened++] = p;
          total_files++;
        }
        fwrite(key + pfx_bytes, 1, keep_bytes, buckets[p]);
      }
      total_in += got;
    }
    fclose(f);
    for(size_t i = 0; i < nopened; i++){ fclose(buckets[opened[i]]); buckets[opened[i]] = NULL; }
    nopened = 0;
  }
  closedir(d);
  free(rbuf); free(opened); free(buckets);
  fprintf(stderr, "[bucket_finalize] %llu keys -> %llu bucket files in %s/ (partition-only, no dedup)\n",
    (unsigned long long)total_in, (unsigned long long)total_files, outdir);
  return 0;
}
