// sha256.h -- minimal streaming SHA-256 (FIPS 180-4), no deps. Shared by every generate/*.c dumper
// (one SHA-256 per candidate, run billions of times, so it's inline C rather than a linked lib).
// Entry point: sha256(data, len, out[32]).
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct { uint32_t s[8]; uint64_t len; uint8_t buf[64]; int n; } sh_t;
static const uint32_t K256[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void shb(sh_t*c,const uint8_t*p){uint32_t w[64],a,b,cc,d,e,f,g,h,t1,t2;for(int i=0;i<16;i++)w[i]=(p[4*i]<<24)|(p[4*i+1]<<16)|(p[4*i+2]<<8)|p[4*i+3];for(int i=16;i<64;i++){uint32_t s0=RR(w[i-15],7)^RR(w[i-15],18)^(w[i-15]>>3),s1=RR(w[i-2],17)^RR(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}a=c->s[0];b=c->s[1];cc=c->s[2];d=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];for(int i=0;i<64;i++){uint32_t S1=RR(e,6)^RR(e,11)^RR(e,25),ch=(e&f)^(~e&g);t1=h+S1+ch+K256[i]+w[i];uint32_t S0=RR(a,2)^RR(a,13)^RR(a,22),mj=(a&b)^(a&cc)^(b&cc);t2=S0+mj;h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;}c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;}
static void shi(sh_t*c){c->s[0]=0x6a09e667;c->s[1]=0xbb67ae85;c->s[2]=0x3c6ef372;c->s[3]=0xa54ff53a;c->s[4]=0x510e527f;c->s[5]=0x9b05688c;c->s[6]=0x1f83d9ab;c->s[7]=0x5be0cd19;c->len=0;c->n=0;}
static void shu(sh_t*c,const uint8_t*p,size_t n){c->len+=n;while(n){int t=64-c->n;if((int)n<t)t=n;memcpy(c->buf+c->n,p,t);c->n+=t;p+=t;n-=t;if(c->n==64){shb(c,c->buf);c->n=0;}}}
static void shf(sh_t*c,uint8_t o[32]){uint64_t b=c->len*8;uint8_t pad=0x80;shu(c,&pad,1);uint8_t z=0;while(c->n!=56)shu(c,&z,1);uint8_t lb[8];for(int i=0;i<8;i++)lb[i]=(b>>(56-8*i))&0xff;shu(c,lb,8);for(int i=0;i<8;i++){o[4*i]=c->s[i]>>24;o[4*i+1]=c->s[i]>>16;o[4*i+2]=c->s[i]>>8;o[4*i+3]=c->s[i];}}
static void sha256(const uint8_t*p,size_t n,uint8_t o[32]){sh_t c;shi(&c);shu(&c,p,n);shf(&c,o);}
