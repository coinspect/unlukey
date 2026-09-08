// Usage:  ./illbloom_dump                                     # 128-bit full space -> /data/illbloom_full_space
//         ./illbloom_dump 256                                 # 256-bit full space -> /data/illbloom_full_space
//         ./illbloom_dump selftest | selftest256               # check entropy fn vs golden vectors
//         ./illbloom_dump <state0> <state1> <outfile|--> [256] # manual state range ("--" = no write,
//                                                               compute-only throughput, no I/O)
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "../entropy.h"
#include "../../common/sha256.h"
#define OUTDIR "/data/illbloom_full_space"

#define REACH_MAIN_END 0x465039b0u
#define REACH_WRAP_LO  0xffff8000u

static int run(uint64_t s0, uint64_t s1, const char *outp, int ebytes, int append){
  const uint32_t sign_n = (ebytes == 32) ? (1u<<15) : (1u<<7);
  const size_t rec = 32;
  int nowrite = (!strcmp(outp,"--"));
  FILE *out = nowrite ? NULL : (!strcmp(outp,"/dev/stdout") ? stdout : fopen(outp, append?"ab":"wb"));
  if(!nowrite && !out){ fprintf(stderr,"open %s failed\n",outp); return 1; }
  const uint64_t total = (s1-s0)*(uint64_t)sign_n;
  fprintf(stderr,"[illbloom%s] state [%llu,%llu) x sign[0,%u) records=%llu (~%.1f GB @%zuB)%s\n",
    ebytes==32?"-256":"", (unsigned long long)s0,(unsigned long long)s1,sign_n,
    (unsigned long long)total, total*(double)rec/1e9, rec, nowrite?" [no write]":"");

  const uint64_t TARGET_BUF = 1ull<<28;
  uint64_t chunk = TARGET_BUF / ((uint64_t)sign_n*rec);
  if(chunk < 1) chunk = 1;
  uint8_t *buf = malloc((size_t)chunk*sign_n*rec);
  struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
  uint64_t done=0;
  for(uint64_t base=s0; base<s1; base+=chunk){
    uint64_t cnt = (base+chunk<=s1) ? chunk : (s1-base);
    for(uint64_t j=0;j<cnt;j++){
      uint32_t state = (uint32_t)(base+j);
      uint8_t *p = buf + (size_t)j*sign_n*rec;
      for(uint32_t sign=0; sign<sign_n; sign++){
        uint8_t *r = p + (size_t)sign*rec;
        uint8_t ent[32];
        if(ebytes==32){
          uint32_t w[8]; f_entropy_from_state256(state, sign, w);
          for(int i=0;i<8;i++){ ent[4*i]=w[i]>>24; ent[4*i+1]=w[i]>>16; ent[4*i+2]=w[i]>>8; ent[4*i+3]=w[i]; }
        } else {
          uint32_t w[4]; f_entropy_from_state(state, sign, w);
          for(int i=0;i<4;i++){ ent[4*i]=w[i]>>24; ent[4*i+1]=w[i]>>16; ent[4*i+2]=w[i]>>8; ent[4*i+3]=w[i]; }
        }
        sha256(ent, ebytes, r);
      }
    }
    if(!nowrite) fwrite(buf,1,(size_t)cnt*sign_n*rec,out);
    done += cnt*sign_n;
  }
  clock_gettime(CLOCK_MONOTONIC,&t1);
  double el=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9, rate=done/el;
  if(out) fclose(out);
  free(buf);
  double reach_states = (double)REACH_MAIN_END + (double)((1ull<<32) - REACH_WRAP_LO);
  double full = reach_states * sign_n;
  fprintf(stderr,"[illbloom%s] %llu records in %.1fs (%.2f Mrec/s). full ~= %.0f recs, %.1f h, %.1f TB\n",
    ebytes==32?"-256":"", (unsigned long long)done, el, rate/1e6, full, full/rate/3600.0, full*rec/1e12);
  return 0;
}

int main(int argc,char**argv){
  if(argc>=2 && !strcmp(argv[1],"selftest"))    return entropy_selftest();
  if(argc>=2 && !strcmp(argv[1],"selftest256")) return entropy_selftest256();
  if(argc==4 || argc==5){
    uint64_t s0=strtoull(argv[1],NULL,0), s1=strtoull(argv[2],NULL,0);
    int ebytes = (argc==5 && !strcmp(argv[4],"256")) ? 32 : 16;
    return run(s0,s1,argv[3],ebytes,0);
  }
  if(argc==1 || (argc==2 && !strcmp(argv[1],"256"))){
    int ebytes = (argc==2) ? 32 : 16;
    mkdir(OUTDIR,0755);
    const char *outp = ebytes==32?OUTDIR"/illbloom256.bin":OUTDIR"/illbloom.bin";
    int r = run(0, REACH_MAIN_END, outp, ebytes, 0);
    if(r) return r;
    return run(REACH_WRAP_LO, 1ull<<32, outp, ebytes, 1);
  }
  fprintf(stderr,"usage: illbloom_dump [256 | selftest | selftest256 | <s0> <s1> <outfile|--> [256]]\n");
  return 2;
}
