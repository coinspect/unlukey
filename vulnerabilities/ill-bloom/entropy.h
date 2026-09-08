// entropy.h -- Ill Bloom (CryptoJS weak RNG) entropy model, both widths: effective-state counter
// (state<<7|sign) -> 16-byte BIP-39 entropy (128-bit/12-word), and (state<<15|sign) -> 32-byte
// entropy (256-bit/24-word) -- same MWC chain run to 8 words instead of 4, 15 sign bits instead
// of 7 (one chain+output flip per word, minus the last word's unused chain flip). The 256-bit
// variant treats the seed as free/unknown (engine-agnostic, matches the 128-bit design already
// used here: "the reference needs no bundled engine") for maximum coverage, rather than assuming
// a specific underlying Math.random() engine. The single source of the algorithm and golden
// vectors, included directly by generate/illbloom_dump.c.
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define A_W 0x4650u
#define Z1S 0xbb770000u
#define Z2S 0x0edd0000u
#define CMUL 0x3ade67b7u
#define TWO32 4294967296.0

static inline uint32_t mwc(uint32_t v){ return (uint32_t)(A_W*(v&0xffffu)) + (uint32_t)((int32_t)v >> 16); }
static inline uint32_t forward_x(uint32_t seed){ return Z2S + mwc(mwc(seed)); }

// Next 32-bit chain state from MWC value mw1 and chain sign s1 (CryptoJS r1*C double math).
static inline uint32_t next_seed_from_state(uint32_t mw1, int s1plus){
  int32_t x1 = (int32_t)(Z1S + mw1);
  double r1 = ((double)x1 / TWO32 + 0.5) * (s1plus ? 1.0 : -1.0);
  double prod = r1 * (double)CMUL * TWO32;      // IEEE-754 double, same as CryptoJS
  return (uint32_t)(int64_t)prod;               // (u32)(long)prod
}

// F'(state m, sign) -> 4 uint32 entropy words.
static inline void f_entropy_from_state(uint32_t m, uint32_t sign, uint32_t w[4]){
  uint32_t x0 = Z2S + mwc(m);
  w[0] = ((sign>>1)&1) ? (x0 ^ 0x80000000u) : (0x80000000u - x0);
  uint32_t cur = next_seed_from_state(m, sign&1);
  for(int i=1;i<4;i++){
    int s2 = (i<3) ? ((sign>>(i*2+1))&1) : ((sign>>6)&1);
    uint32_t x = forward_x(cur);
    w[i] = s2 ? (x ^ 0x80000000u) : (0x80000000u - x);
    if(i<3){ int s1=(sign>>(i*2))&1; cur = next_seed_from_state(mwc(cur), s1); }
  }
}

// 16-byte entropy for an effective-state counter (state<<7|sign), words big-endian.
static inline void entropy_from_counter(uint64_t counter, uint8_t out[16]){
  uint32_t state=(uint32_t)(counter>>7), sign=(uint32_t)(counter&0x7f);
  uint32_t w[4]; f_entropy_from_state(state, sign, w);
  for(int i=0;i<4;i++){ out[4*i]=w[i]>>24; out[4*i+1]=w[i]>>16; out[4*i+2]=w[i]>>8; out[4*i+3]=w[i]; }
}

// F'(state m, sign) -> 8 uint32 entropy words (256-bit/24-word variant). Same chain as
// f_entropy_from_state, generalized: 8 words, 15 effective sign bits (bit(2i)=chain flip i<7,
// bit(2i+1)=word flip i<7, bit14=word flip for the last word).
static inline void f_entropy_from_state256(uint32_t m, uint32_t sign, uint32_t w[8]){
  uint32_t x0 = Z2S + mwc(m);
  w[0] = ((sign>>1)&1) ? (x0 ^ 0x80000000u) : (0x80000000u - x0);
  uint32_t cur = next_seed_from_state(m, sign&1);
  for(int i=1;i<8;i++){
    int s2 = (i<7) ? ((sign>>(i*2+1))&1) : ((sign>>14)&1);
    uint32_t x = forward_x(cur);
    w[i] = s2 ? (x ^ 0x80000000u) : (0x80000000u - x);
    if(i<7){ int s1=(sign>>(i*2))&1; cur = next_seed_from_state(mwc(cur), s1); }
  }
}

// 32-byte entropy for an effective-state counter (state<<15|sign), words big-endian.
static inline void entropy_from_counter256(uint64_t counter, uint8_t out[32]){
  uint32_t state=(uint32_t)(counter>>15), sign=(uint32_t)(counter&0x7fffu);
  uint32_t w[8]; f_entropy_from_state256(state, sign, w);
  for(int i=0;i<8;i++){ out[4*i]=w[i]>>24; out[4*i+1]=w[i]>>16; out[4*i+2]=w[i]>>8; out[4*i+3]=w[i]; }
}

// golden vectors: counter -> 16-byte entropy hex. counter 0 is the documented canonical vector;
// the rest are (counter, entropy) pairs from the C model: engine_zoo minstd48271 { sweep 128 S S+1 | gen S }.
static const struct { uint64_t counter; const char *want; } ENTROPY_GOLDEN[] = {
  {0x0000000000ull, "7123000046089b516efdc72c6af30279"},
  {0x1823073279ull, "6d2ef87ac5b332b794d4662199a12f31"},
  {0x0d1e54b4e5ull, "429b3ef46cd6e5fea5ee0889b21f5ca0"},
  {0x203ff3778bull, "ce4ac52fc2f518774f68acdb5bb117dd"},
  {0x00b57ddf2aull, "d401a0ca8fcc6436cbd290692f16c5d7"},
};
#define ENTROPY_GOLDEN_N (sizeof(ENTROPY_GOLDEN)/sizeof(ENTROPY_GOLDEN[0]))

static inline int entropy_selftest(void){
  int fail = 0;
  for(size_t k=0;k<ENTROPY_GOLDEN_N;k++){
    uint8_t got[16]; entropy_from_counter(ENTROPY_GOLDEN[k].counter, got);
    char hex[33]; for(int i=0;i<16;i++) sprintf(hex+2*i,"%02x",got[i]);
    int ok = !strcmp(hex, ENTROPY_GOLDEN[k].want);
    if(!ok) fail++;
    printf("%s entropy(0x%010llx) = %s\n", ok?"OK  ":"FAIL", (unsigned long long)ENTROPY_GOLDEN[k].counter, hex);
  }
  printf("selftest: %s\n", fail?"FAIL":"PASS");
  return fail?1:0;
}

// 256-bit golden vectors: counter (state<<15|sign) -> 32-byte entropy hex. counter 0 matches the
// 128-bit counter-0 vector's first 16 bytes exactly (same MWC chain, state=0 either way) -- a
// built-in cross-check against the proven 128-bit path. Cross-validated against an independent
// JS reimplementation of the same effective-state model (fEntropyFromState256).
static const struct { uint64_t counter; const char *want; } ENTROPY_GOLDEN256[] = {
  {0x000000000000ull, "7123000046089b516efdc72c6af30279645a49c76eb4674c53e2747060f92c5f"},
  {0x000000008000ull, "7122b9b06e5f511d42cc6909432ecaeb3061f23c4355039e32667e132b1e3caf"},
  {0x091a2b3c1234ull, "5963184c33faaf28b5a726396c5805bd95f376816e98b3126f26523b527bede7"},
  {0x6f56df77ffffull, "c34de35db190b906a7f45aefbef46b7acbfb678dbcc180169acb4799ca3bcac6"},
  {0x005580668001ull, "70eab1456f60d21b3675f29d50f363564f5b4c6b2dabdd0e52d6507c2c3ec557"},
};
#define ENTROPY_GOLDEN256_N (sizeof(ENTROPY_GOLDEN256)/sizeof(ENTROPY_GOLDEN256[0]))

static inline int entropy_selftest256(void){
  int fail = 0;
  for(size_t k=0;k<ENTROPY_GOLDEN256_N;k++){
    uint8_t got[32]; entropy_from_counter256(ENTROPY_GOLDEN256[k].counter, got);
    char hex[65]; for(int i=0;i<32;i++) sprintf(hex+2*i,"%02x",got[i]);
    int ok = !strcmp(hex, ENTROPY_GOLDEN256[k].want);
    if(!ok) fail++;
    printf("%s entropy256(0x%012llx) = %s\n", ok?"OK  ":"FAIL", (unsigned long long)ENTROPY_GOLDEN256[k].counter, hex);
  }
  printf("selftest256: %s\n", fail?"FAIL":"PASS");
  return fail?1:0;
}
