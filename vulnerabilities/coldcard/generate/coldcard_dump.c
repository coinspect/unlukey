#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "../entropy.h"
#define REC 32

static double now(){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec + t.tv_nsec*1e-9; }

#define OUTDIR "/data/coldcard_full_space"

#define Y_LO 0x00u
#define Y_HI 0xffu
#define NLOW 65536u
static const uint32_t NY = (Y_HI - Y_LO + 1);
static inline uint32_t pad_of_index(uint32_t i){
  return ((Y_LO + (i / NLOW)) << 16) | (i % NLOW);
}

static int run(uint32_t i0,uint32_t i1,uint32_t tmax,uint32_t adv,int scramble,const char*outp){
  const uint32_t PRE_LO=2,PRE_HI=6,POST=2;
  const uint32_t npre = scramble ? (PRE_HI-PRE_LO+1) : 1;
  int nowrite=(strcmp(outp,"--")==0);
  FILE*out=NULL;
  if(!nowrite){
    if(!strcmp(outp,"/dev/stdout")) out=stdout;
    else{ mkdir(OUTDIR,0755); out=fopen(outp,"wb"); if(!out){ perror("fopen"); return 1; } }
  }
  const uint64_t total=(uint64_t)(i1-i0)*(uint64_t)tmax*npre;
  fprintf(stderr,"[%s adv=%u] pad-idx [%u,%u) touch[0,%u)%s records=%llu (~%.1f GB @%dB)%s%s\n",
    scramble?"scramble":"normal",adv,i0,i1,tmax,scramble?" pre[2..6] post=2":"",
    (unsigned long long)total,total*(double)REC/1e9,REC,
    nowrite?" [NO WRITE]":" -> ",nowrite?"":outp);
  double t0=now();
  const uint32_t BLK=4096;
  uint64_t done=0;
  for(uint32_t base=i0; base<i1; base+=BLK){
    uint32_t hi=base+BLK<i1?base+BLK:i1, cnt=hi-base;
    size_t per_pad=(size_t)tmax*npre*REC;
    uint8_t*chunk=malloc((size_t)cnt*per_pad);
    if(!chunk){ fprintf(stderr,"OOM\n"); if(out)fclose(out); return 1; }
    for(uint32_t pi=0; pi<cnt; pi++){
      uint32_t pad=pad_of_index(base+pi); uint8_t*rp=chunk+(size_t)pi*per_pad;
      for(uint32_t pre=(scramble?PRE_LO:0); pre<=(scramble?PRE_HI:0); pre++)
        for(uint32_t t=0;t<tmax;t++){
          uint8_t ent[32];
          entropy_of(pad,t,adv,pre,scramble?POST:0,ent);
          sha256(ent,32,rp);
          rp+=REC;
        }
    }
    if(!nowrite) fwrite(chunk,1,(size_t)cnt*per_pad,out);
    free(chunk);
    done+=(uint64_t)cnt*tmax*npre;
    double el=now()-t0,rate=done/el;
    fprintf(stderr,"\r  %llu/%llu (%.1f%%) %.2f Mrec/s %.0fs ETA %.0fs   ",
      (unsigned long long)done,(unsigned long long)total,100.0*done/total,rate/1e6,el,(total-done)/rate);
    fflush(stderr);
  }
  double el=now()-t0,rate=done/el;
  fprintf(stderr,"\n[%s] done: %llu recs in %.1fs = %.2f Mrec/s\n",
    scramble?"scramble":"normal",(unsigned long long)done,el,rate/1e6);
  double full=(double)NY*(double)NLOW*1024.0*(double)npre;
  fprintf(stderr,"[%s] extrapolated full (%.2e recs): %.0f s (%.1f h), %.2f TB @%dB\n",
    scramble?"scramble":"normal",full,full/rate,full/rate/3600.0,full*REC/1e12,REC);
  if(out)fclose(out);
  return 0;
}

static const uint32_t ADV_SET[] = {0, 18};
#define ADV_N (sizeof(ADV_SET)/sizeof(ADV_SET[0]))

int main(int argc,char**argv){
  const uint32_t NPAD = NY*NLOW;
  const uint32_t FULL_TOUCH=1024u;
  if(argc>=2 && !strcmp(argv[1],"selftest")) return entropy_selftest();
  if(argc==1){
    for(size_t a=0;a<ADV_N;a++){
      char pn[256],ps[256];
      snprintf(pn,sizeof pn,OUTDIR"/coldcard_normal_a%u.bin",ADV_SET[a]);
      snprintf(ps,sizeof ps,OUTDIR"/coldcard_scramble_a%u.bin",ADV_SET[a]);
      int r=run(0,NPAD,FULL_TOUCH,ADV_SET[a],0,pn); if(r) return r;
      r=run(0,NPAD,FULL_TOUCH,ADV_SET[a],1,ps);     if(r) return r;
    }
    return 0;
  }
  if(argc>=6){
    uint32_t i0=(uint32_t)strtoul(argv[1],0,0),i1=(uint32_t)strtoul(argv[2],0,0),tmax=(uint32_t)strtoul(argv[3],0,0);
    uint32_t adv=(uint32_t)strtoul(argv[4],0,0);
    int scr=(argc>=7 && strcmp(argv[6],"scramble")==0);
    return run(i0,i1,tmax,adv,scr,argv[5]);
  }
  fprintf(stderr,"usage: %s                # generate EVERYTHING (adv{0,18} x normal + scramble)\n",argv[0]);
  fprintf(stderr,"       %s selftest        # verify the entropy fn against golden vectors\n",argv[0]);
  fprintf(stderr,"       %s <i0> <i1> <touchmax> <adv> <outfile|--> [normal|scramble]   # manual (pad indices 0..%u)\n",argv[0],NPAD);
  return 2;
}
