#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>

static void mkdir_p(const char *path){
  char buf[1024]; snprintf(buf, sizeof(buf), "%s", path);
  for(char *p = buf + 1; *p; p++){
    if(*p == '/'){ *p = 0; mkdir(buf, 0755); *p = '/'; }
  }
  mkdir(buf, 0755);
}

// MSB-first -- must match bucket_finalize's packing.
static uint32_t prefix_of(const uint8_t *h, int bits){
  uint32_t v = 0; int got = 0, i = 0;
  while(got < bits){
    int take = bits - got; if(take > 8) take = 8;
    v = (v << take) | (uint32_t)(h[i] >> (8 - take));
    got += take; i++;
  }
  return v;
}

int main(int argc, char **argv){
  if(argc < 3){
    fprintf(stderr, "usage: %s <shard-bits> <shard-dir> [infile|-] ...\n", argv[0]);
    return 2;
  }
  int bits = atoi(argv[1]);
  if(bits < 1 || bits > 24){ fprintf(stderr, "shard-bits must be 1..24\n"); return 2; }
  const char *shard_dir = argv[2];
  size_t rec = 32;
  uint32_t nshards = 1u << bits;
  int hexw = (bits + 3) / 4;

  mkdir_p(shard_dir);

  struct rlimit rl;
  if(getrlimit(RLIMIT_NOFILE, &rl) == 0){
    rlim_t want = (rlim_t)nshards + 16;
    if(rl.rlim_cur < want){
      rl.rlim_cur = (rl.rlim_max != RLIM_INFINITY && rl.rlim_max < want) ? rl.rlim_max : want;
      setrlimit(RLIMIT_NOFILE, &rl);
      getrlimit(RLIMIT_NOFILE, &rl);
    }
    if((uint64_t)rl.rlim_cur < (uint64_t)nshards + 16)
      fprintf(stderr, "[bucket_partition] warning: fd limit %llu < %u shards needed -- "
                       "run `ulimit -n %llu` first\n",
              (unsigned long long)rl.rlim_cur, nshards, (unsigned long long)nshards + 16);
  }

  FILE **shards = calloc(nshards, sizeof(FILE*));
  for(uint32_t s = 0; s < nshards; s++){
    char path[1024];
    snprintf(path, sizeof(path), "%s/%0*x", shard_dir, hexw, s);
    shards[s] = fopen(path, "ab");
    if(!shards[s]){ perror(path); return 1; }
  }

  int nin = argc - 3;
  const char *default_stdin = "-";
  const char **infiles = nin > 0 ? (const char**)&argv[3] : &default_stdin;
  if(nin == 0) nin = 1;

  uint8_t *buf = malloc(rec);
  uint64_t total = 0;
  for(int a = 0; a < nin; a++){
    int is_stdin = strcmp(infiles[a], "-") == 0;
    FILE *f = is_stdin ? stdin : fopen(infiles[a], "rb");
    if(!f){ perror(infiles[a]); return 1; }
    setvbuf(f, NULL, _IOFBF, 1<<20);
    size_t got;
    while((got = fread(buf, 1, rec, f)) == rec){
      uint32_t s = prefix_of(buf, bits);
      fwrite(buf, 1, 32, shards[s]);
      total++;
    }
    if(got != 0) fprintf(stderr, "[bucket_partition] warning: %s ends with a partial record, ignored\n", infiles[a]);
    if(!is_stdin) fclose(f);
  }
  free(buf);

  for(uint32_t s = 0; s < nshards; s++) fclose(shards[s]);
  free(shards);
  fprintf(stderr, "[bucket_partition] partitioned %llu records into %u shards under %s/\n",
    (unsigned long long)total, nshards, shard_dir);
  return 0;
}
