// kat_gen_pass.cpp  —  SHRINCS Known-Answer Tests: correct data (PASS cases)
//
// Select the parameter set at compile time:
//   -DSHRINCS_B   →  SHRINCS-B  (HSF=158, L=16, W=256, SWN=2040)   [default]
//   -DSHRINCS_L   →  SHRINCS-L  (HSF=206, L=64, W=4,   SWN=140)   
//
// Build examples (from repo root):
//   Step 1
//     gcc -O2 -c kat/rng.c -I./kat -o rng.o
//
//   Step 2
//   SHRINCS-B:
//     g++ -std=c++17 -O2 -DSHRINCS_B \
//         kat/kat_gen_pass.cpp rng.o \
//         src/shrincs.cpp src/uxmss.cpp src/xmss.cpp src/pors_fp.cpp \
//         src/wots_c.cpp src/hash.cpp src/address.cpp \
//         -I./include -I./kat -lssl -lcrypto -o kat_pass_B
//     ./kat_pass_B
//
//   SHRINCS-L:
//     g++ -std=c++17 -O2 -DSHRINCS_L \
//         kat/kat_gen_pass.cpp rng.o \
//         src/shrincs.cpp src/uxmss.cpp src/xmss.cpp src/pors_fp.cpp \
//         src/wots_c.cpp src/hash.cpp src/address.cpp \
//         -I./include -I./kat -lssl -lcrypto -o kat_pass_L
//     ./kat_pass_L
//
// Output: SHRINCS-{B|L}_pass.rsp

#include "shrincs.h"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <stdexcept>
extern "C" {
    #include "rng.h"
}

using namespace Parameters;
using namespace SHRINCS;

#ifdef SHRINCS_B
    static constexpr const char* VARIANT_NAME = "B";
    static unsigned char MASTER_SEED[48] = {
        0x42,0x50,0x41,0x53,0x53,0x5f,0x42,0x00,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
    };
#else
    static constexpr const char* VARIANT_NAME = "L";
    static unsigned char MASTER_SEED[48] = {
        0x4c,0x50,0x41,0x53,0x53,0x5f,0x4c,0x00,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
    };
#endif


static void fprint_hex(FILE* f, const unsigned char* buf, size_t n)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        fputc(H[buf[i] >> 4],  f);
        fputc(H[buf[i] & 0xf], f);
    }
}

static void keygen(const unsigned char seed3N[3*N],
                   PublicKey& pk, SecretKey& sk, State& st)
{
    shrincs_restore(seed3N, pk, sk, st);
    st.valid = true;
}

static uint32_t sf_siglen(uint32_t q)
{
    return N + WOTS_SIGN_LEN + (q > HSF ? HSF : q) * N;
}

static void write_record(FILE* f, int count, const char* label,
                         const unsigned char seed3N[3*N],
                         size_t mlen, const unsigned char* msg,
                         const PublicKey& pk, const SecretKey& sk,
                         const unsigned char* sig, uint32_t siglen,
                         bool verify_result)
{
    fprintf(f, "count  = %d\n", count);
    fprintf(f, "label  = %s\n", label);
    fprintf(f, "seed   = "); fprint_hex(f, seed3N, 3*N);             fputc('\n', f);
    fprintf(f, "mlen   = %zu\n", mlen);
    fprintf(f, "msg    = "); fprint_hex(f, msg, mlen);                fputc('\n', f);
    fprintf(f, "pk     = ");
    fprint_hex(f, pk.seed.data(), N); fprint_hex(f, pk.root.data(), N);
    fputc('\n', f);
    fprintf(f, "sk     = ");
    fprint_hex(f, sk.seed.data(), N);    fprint_hex(f, sk.prf.data(), N);
    fprint_hex(f, sk.sf.data(), N);      fprint_hex(f, sk.sl.data(), N);
    fprint_hex(f, sk.pk.seed.data(), N); fprint_hex(f, sk.pk.root.data(), N);
    fputc('\n', f);
    fprintf(f, "sig    = "); fprint_hex(f, sig, siglen);              fputc('\n', f);
    fprintf(f, "siglen = %u\n", siglen);
    fprintf(f, "result = %s\n\n", verify_result ? "Pass" : "Fail");
}

static void advance_to(SecretKey& sk, State& st, uint32_t target_q)
{
    std::vector<unsigned char> dummy = std::vector<unsigned char>(32, 0);
    
    while (st.q < target_q - 1) {
        unsigned char* tmp = shrincs_sign_stateful(dummy, sk, st);
        delete[] tmp;
    }
}

static const int N_MSG = 25;
static size_t MSG_LENS[N_MSG];

static void init_msg_lens()
{
    for (int i = 0; i < N_MSG; ++i)
        MSG_LENS[i] = 33*(i*i+1);
}

static const uint32_t SF_QS[] = {
    1, 2, 3, 5, 10, 20, 50, 100,
    HSF / 4,
    HSF / 2,
    HSF - 2,
    HSF - 1,
    HSF,
    HSF + 1
};
static const int N_SFQ = sizeof(SF_QS) / sizeof(SF_QS[0]);


int main()
{
    init_msg_lens();
    randombytes_init(MASTER_SEED, NULL, 256);

    char outfile[64];
    snprintf(outfile, sizeof(outfile), "SHRINCS-%s_pass.rsp", VARIANT_NAME);
    FILE* f = fopen(outfile, "w");
    if (!f) { perror(outfile); return 1; }

    fprintf(f, "# SHRINCS-%s Known-Answer Tests — PASS (correct data)\n", VARIANT_NAME);
    fprintf(f, "# result is written from actual shrincs_verify return value.\n");
    fprintf(f, "# If result = Fail appears, the library has a bug — check stderr.\n\n");

    int count = 0;

    for (int mi = 0; mi < N_MSG; ++mi)
    {
        size_t mlen = MSG_LENS[mi];

        unsigned char seed[3*N];
        randombytes(seed, 3*N);

        std::vector<unsigned char> msg = std::vector<unsigned char>(mlen);
        randombytes(msg.data(), mlen);

        {
            PublicKey pk; SecretKey sk; State st;
            keygen(seed, pk, sk, st);

            unsigned char* sig = shrincs_sign_stateless(msg, sk);

            bool ok = false;
            try { ok = shrincs_verify(msg, sig, SL_SIZE, pk); }
            catch (...) {}

            if (!ok)
                fprintf(stderr, "WARN: stateless self-check failed mlen=%zu\n", mlen);

            char lbl[128];
            snprintf(lbl, sizeof(lbl),
                     "SHRINCS-%s stateless mlen=%zu", VARIANT_NAME, mlen);
            write_record(f, count++, lbl, seed, mlen, msg.data(), pk, sk, sig, SL_SIZE, ok);
            delete[] sig;
        }

        for (int qi = 0; qi < N_SFQ; ++qi)
        {
            uint32_t target_q = SF_QS[qi];

            PublicKey pk; SecretKey sk; State st;
            keygen(seed, pk, sk, st);
            advance_to(sk, st, target_q);

            unsigned char* sig = shrincs_sign_stateful(msg, sk, st);
            uint32_t slen = sf_siglen(target_q);

            bool ok = false;
            try { ok = shrincs_verify(msg, sig, slen, pk); }
            catch (...) {}

            if (!ok)
                fprintf(stderr, "WARN: stateful self-check failed q=%u mlen=%zu\n",
                        target_q, mlen);

            char lbl[128];
            snprintf(lbl, sizeof(lbl),
                     "SHRINCS-%s stateful q=%u mlen=%zu",
                     VARIANT_NAME, target_q, mlen);
            write_record(f, count++, lbl, seed, mlen, msg.data(), pk, sk, sig, slen, ok);
            delete[] sig;
        }
    }

    fprintf(f, "# Total records: %d\n", count);
    fclose(f);
    printf("Wrote %d records to %s\n", count, outfile);
    return 0;
}