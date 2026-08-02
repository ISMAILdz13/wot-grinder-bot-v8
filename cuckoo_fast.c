
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ===== SHA-256 (for key hashing, same as Python hashlib.sha256) =====
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
static uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
void sha256(const uint8_t*msg,size_t len,uint8_t out[32]){
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint64_t bit_len=(uint64_t)len*8;
    size_t plen=len+1; while(plen%64!=56)plen++;plen+=8;
    uint8_t*p=(uint8_t*)calloc(plen,1);
    memcpy(p,msg,len);p[len]=0x80;
    for(int i=0;i<8;i++)p[plen-8+i]=(uint8_t)(bit_len>>(56-i*8));
    for(size_t blk=0;blk<plen;blk+=64){
        uint32_t w[64];
        for(int i=0;i<16;i++)w[i]=((uint32_t)p[blk+i*4]<<24)|((uint32_t)p[blk+i*4+1]<<16)|((uint32_t)p[blk+i*4+2]<<8)|p[blk+i*4+3];
        for(int i=16;i<64;i++){uint32_t s0=ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3),s1=ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;i++){uint32_t S1=ROR32(e,6)^ROR32(e,11)^ROR32(e,25),ch=(e&f)^(~e&g),t1=hh+S1+ch+K[i]+w[i],S0=ROR32(a,2)^ROR32(a,13)^ROR32(a,22),maj=(a&b)^(a&c)^(b&c),t2=S0+maj;hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    free(p);
    for(int i=0;i<8;i++){out[i*4]=(h[i]>>24)&0xFF;out[i*4+1]=(h[i]>>16)&0xFF;out[i*4+2]=(h[i]>>8)&0xFF;out[i*4+3]=h[i]&0xFF;}
}

// ===== SipHash-2-4 =====
#define ROTL64(x,n) (((x)<<(n))|((x)>>(64-(n))))
#define SIP_ROUND v0+=v1;v1=ROTL64(v1,13);v1^=v0;v0=ROTL64(v0,32);v2+=v3;v3=ROTL64(v3,16);v3^=v2;v0+=v3;v3=ROTL64(v3,21);v3^=v0;v2+=v1;v1=ROTL64(v1,17);v1^=v2;v2=ROTL64(v2,32);
static uint64_t siphash24(uint64_t k0,uint64_t k1,uint64_t nonce){
    uint64_t v0=k0^0x736f6d6570736575ULL,v1=k1^0x646f72616e646f6dULL,v2=k0^0x6c7967656e657261ULL,v3=k1^0x7465646279746573ULL;
    v3^=nonce;SIP_ROUND;SIP_ROUND;v0^=nonce;v2^=0xff;SIP_ROUND;SIP_ROUND;SIP_ROUND;SIP_ROUND;
    return v0^v1^v2^v3;
}

// ===== Cuckoo Cycle Solver =====
#define SIZESHIFT 20
#define PROOFSIZE 42
#define SIZE (1ULL<<SIZESHIFT)
#define HALFSIZE (SIZE/2)
#define NODEMASK (HALFSIZE-1)
#define MAXPATH 8192

static uint32_t graph[HALFSIZE];
static uint32_t path_us[MAXPATH], path_vs[MAXPATH];

static int path(uint32_t u, uint32_t *us) {
    int len=0;
    for(;u;u=graph[u-1]) {
        if(++len>=MAXPATH) return -1;
        us[len-1]=u;
    }
    return len;
}

// solution array must be uint32_t[42]
int cuckoo_solve(const char* key_str, uint64_t max_nonce, uint32_t* sol) {
    uint8_t hash[32];
    sha256((const uint8_t*)key_str, strlen(key_str), hash);
    uint64_t k0=0,k1=0;
    for(int i=0;i<8;i++) k0|=((uint64_t)hash[i]<<(i*8));
    for(int i=0;i<8;i++) k1|=((uint64_t)hash[8+i]<<(i*8));
    
    memset(graph,0,sizeof(graph));
    
    for(uint64_t nonce=0;nonce<max_nonce;nonce++){
        uint32_t u0=(uint32_t)(siphash24(k0,k1,2*nonce)&NODEMASK)+1;
        uint32_t v0=(uint32_t)(siphash24(k0,k1,2*nonce+1)&NODEMASK)+1+HALFSIZE;
        
        int nu=path(u0,path_us);
        int nv=path(v0,path_vs);
        if(nu<0||nv<0) continue;
        
        // find common ancestor
        int i=nu-1,j=nv-1;
        if(path_us[i]!=path_vs[j]) { // no common root yet
            if(nu<=nv) graph[u0-1]=v0;
            else graph[v0-1]=u0;
            continue;
        }
        // trim common tail
        while(i>=0&&j>=0&&path_us[i]==path_vs[j]){i--;j--;}
        int cycle_len=i+j+2;
        if(cycle_len==PROOFSIZE-1){
            // found! collect nonces by re-scanning
            // For now store the triggering nonce and return success
            // Python will do full extraction
            sol[0]=(uint32_t)nonce;
            return 1;
        }
        if(nu<=nv) graph[u0-1]=v0;
        else graph[v0-1]=u0;
    }
    return 0;
}

int main(int argc,char**argv){
    if(argc<3){printf("usage: cuckoo_solve KEY MAX_NONCE\n");return 1;}
    uint32_t sol[42]={0};
    int found=cuckoo_solve(argv[1],(uint64_t)atoll(argv[2]),sol);
    if(found) printf("HINT %u\n",sol[0]);
    else printf("NONE\n");
    return 0;
}
