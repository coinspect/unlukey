// entropy.h -- Coldcard Mk2/Mk3 weak-seed entropy model: (pad, touch [, pre, post]) -> 32-byte
// BIP-39 entropy. Word i = ys(chip) ^ ys(ngu): ngu is the libngu constant (pad=0x0a8ce26f, n=69,
// d=233); chip is seeded (pad, n=d=0) as on Mk3. The single source of the algorithm and golden
// vectors, included directly by generate/coldcard_dump.c.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../common/sha256.h"

#define NGU_PAD 0x0a8ce26fu

// ---- Yasmarang + get_random32 (verbatim from coldcard_gen.c) ----
typedef struct { uint32_t pad, n, d; uint8_t dat; } yas_t;
static inline uint32_t ys(yas_t*c){ // Yasmarang step
  c->pad += c->dat + c->d*c->n;
  c->pad = (c->pad<<3) + (c->pad>>29);
  c->n = c->pad|2;
  c->d ^= (c->pad<<31) + (c->pad>>1);
  c->dat ^= (char)c->pad ^ (c->d>>8) ^ 1;
  return c->pad ^ (c->d<<5) ^ (c->pad>>18) ^ ((uint32_t)c->dat<<1);
}
static inline int bit_length(uint32_t x){ if(!x) return 0; int b=1; while(x>>b) b++; return b; }
static inline int rand_below(yas_t*ngu, yas_t*chip, int mx){ // rand_below(mx) drawing from ys(ngu) ^ ys(chip)
  if(mx<=1) return 0;
  int bl=bit_length(mx); uint32_t mask=(2u<<bl)-1;
  uint32_t pt=ys(ngu); pt^=ys(chip);
  for(;;){ int rv=(int)(pt&mask); if(rv<mx) return rv; pt^=ys(ngu); }
}
static inline void shuffle(yas_t*ngu, yas_t*chip){ rand_below(ngu,chip,4); rand_below(ngu,chip,3); rand_below(ngu,chip,2); }
static inline void shuffle_pin(yas_t*ngu, yas_t*chip){ for(int m=10;m>=2;m--) rand_below(ngu,chip,m); }

// get_random32: boot ngu, advance it by `adv` raw ys(ngu) calls (ngu_adv / V2 -- models prior
// persistent-PRNG draws from earlier keypad logins; adv=0 is V1/fresh, a strict superset), then
// pre==0 => normal; pre!=0 => Scramble Keys (shuffle_pin, pre x shuffle, shuffle_pin, post x
// shuffle), then touch x shuffle, then 8 words (chip ^ ngu), LE. Verbatim from coldcard_gen.c.
static inline void device_raw(uint32_t chip_pad, uint32_t ngu_pad, uint32_t adv, uint32_t pre, uint32_t post, uint32_t touch, uint8_t out[32]){
  yas_t ngu={ngu_pad,69,233,0}, chip={chip_pad,0,0,0};
  for(uint32_t i=0;i<adv;i++) ys(&ngu);          // ngu_adv (V2): k prior persistent-PRNG advances
  if(pre!=0){
    shuffle_pin(&ngu,&chip); for(uint32_t i=0;i<pre;i++)  shuffle(&ngu,&chip);
    shuffle_pin(&ngu,&chip); for(uint32_t i=0;i<post;i++) shuffle(&ngu,&chip);
  }
  for(uint32_t i=0;i<touch;i++) shuffle(&ngu,&chip);
  for(int i=0;i<8;i++){ uint32_t x=ys(&chip)^ys(&ngu);
    out[4*i]=x&0xff; out[4*i+1]=(x>>8)&0xff; out[4*i+2]=(x>>16)&0xff; out[4*i+3]=(x>>24)&0xff; }
}

// 32-byte BIP-39 entropy for (pad, touch, adv [, pre, post]): device_raw() then a single SHA-256.
// adv=0: V1/fresh; adv>0: V2 (prior ngu advances). pre=0: normal; pre!=0: Scramble Keys.
static inline void entropy_of(uint32_t pad, uint32_t touch, uint32_t adv, uint32_t pre, uint32_t post, uint8_t out[32]){
  uint8_t raw[32];
  device_raw(pad, NGU_PAD, adv, pre, post, touch, raw);
  sha256(raw, 32, out);
}

// golden vectors: (pad, touch, adv, pre, post) -> 32-byte entropy hex. V1 (adv=0, no scramble) is
// device-confirmed; the adv=18 vector is the V2 anchor from hashcat-brujo's coldcard_gen.c.
static const struct { uint32_t pad, touch, adv, pre, post; const char *want; } ENTROPY_GOLDEN[] = {
  {0x001f20c9, 12, 0,  0, 0, "ae27dd95b9bea864aec37e0416377e4c9a073fc2d331867598297c8e8117ad08"},
  {0x001f20c9, 12, 0,  2, 2, "120b443edd623c49bc9b989c3807aaf6c66795722fe561f100a03a6006291fbc"},
  {0x001f20c9, 12, 0,  4, 4, "ca568191caec1cf071142479324ee14b69efffa96f8379a01d2dfdbc8d2826cc"},
  {0x001f20c9, 0,  0,  6, 6, "e8e3ad1c8bda58261e7350c136dedc185f111874b534d897c76281e3cd5dfd64"},
  {0x001f20c9, 12, 18, 0, 0, "72a79defdd48ddd247e59c85e5fcca1d5bbc231142d67e11932cd254b05e9dbf"},
};
#define ENTROPY_GOLDEN_N (sizeof(ENTROPY_GOLDEN)/sizeof(ENTROPY_GOLDEN[0]))

static inline int entropy_selftest(void){
  int fail = 0;
  for(size_t k=0;k<ENTROPY_GOLDEN_N;k++){
    uint8_t got[32];
    entropy_of(ENTROPY_GOLDEN[k].pad, ENTROPY_GOLDEN[k].touch, ENTROPY_GOLDEN[k].adv, ENTROPY_GOLDEN[k].pre, ENTROPY_GOLDEN[k].post, got);
    char hex[65]; for(int i=0;i<32;i++) sprintf(hex+2*i,"%02x",got[i]);
    int ok = !strcmp(hex, ENTROPY_GOLDEN[k].want);
    if(!ok) fail++;
    printf("%s entropy(0x%08x, touch=%u, adv=%u, pre=%u, post=%u) = %.16s...\n", ok?"OK  ":"FAIL",
      ENTROPY_GOLDEN[k].pad, ENTROPY_GOLDEN[k].touch, ENTROPY_GOLDEN[k].adv, ENTROPY_GOLDEN[k].pre, ENTROPY_GOLDEN[k].post, hex);
  }
  printf("selftest: %s\n", fail?"FAIL":"PASS");
  return fail?1:0;
}
