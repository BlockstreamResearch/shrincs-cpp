// truncation_bug_demo.cpp
//
// Build (from repo root):
//  gcc -O2 -c kat/rng.c -I./kat -o rng.o
//
//  g++ -std=c++17 -O2 -DSHRINCS_B \
//    kat/truncation_bug_demo.cpp rng.o \
//    src/shrincs.cpp src/uxmss.cpp src/xmss.cpp src/fors_c.cpp \
//    src/wots_c.cpp src/hash.cpp src/address.cpp \
//    -I./include -I./kat -lssl -lcrypto -o truncation_bug_demo
//   ./truncation_bug_demo

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

static unsigned char MASTER_SEED[48] = {
    0x54,0x52,0x55,0x4e,0x43,0x5f,0x42,0x55,
    0x47,0x5f,0x44,0x45,0x4d,0x4f,0x00,0x00,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
};

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

static unsigned char* corrupt_at(const unsigned char* data, size_t len,
                                  uint32_t offset, unsigned char mask)
{
    unsigned char* bad = new unsigned char[len];
    memcpy(bad, data, len);
    bad[offset] ^= mask;
    return bad;
}

static void random_offset_in(uint32_t lo, uint32_t hi,
                              uint32_t& out_offset, unsigned char& out_mask)
{
    unsigned char rbuf[5];
    randombytes(rbuf, 5);
    uint32_t range = hi - lo;
    out_offset = lo + (((uint32_t)rbuf[0] << 24 | (uint32_t)rbuf[1] << 16 |
                         (uint32_t)rbuf[2] << 8  | rbuf[3]) % range);
    out_mask = rbuf[4];
    if (out_mask == 0) out_mask = 0x01;
}

static void write_record(FILE* f, int count, const char* label,
                          const unsigned char* seed3N,
                          size_t mlen, const unsigned char* msg,
                          const PublicKey& pk,
                          const unsigned char* sig, uint32_t siglen,
                          const unsigned char* corrupted_msg,
                          uint32_t corrupt_offset, unsigned char corrupt_mask,
                          bool verify_result)
{
    fprintf(f, "count          = %d\n",   count);
    fprintf(f, "label          = %s\n",   label);
    fprintf(f, "seed           = "); fprint_hex(f, seed3N, 3*N);         fputc('\n', f);
    fprintf(f, "mlen           = %zu\n",  mlen);
    fprintf(f, "msg            = "); fprint_hex(f, msg, mlen);            fputc('\n', f);
    fprintf(f, "pk             = ");
    fprint_hex(f, pk.seed.data(), N); fprint_hex(f, pk.root.data(), N);  fputc('\n', f);
    fprintf(f, "sig            = "); fprint_hex(f, sig, siglen);          fputc('\n', f);
    fprintf(f, "siglen         = %u\n",   siglen);
    fprintf(f, "corrupt_offset = %u\n",   corrupt_offset);
    fprintf(f, "corrupt_mask   = 0x%02x\n", corrupt_mask);
    fprintf(f, "msg corrupted  = "); fprint_hex(f, corrupted_msg, mlen); fputc('\n', f);
    fprintf(f, "result         = %s\n\n", verify_result ? "Pass" : "Fail");
}


int main()
{
    randombytes_init(MASTER_SEED, NULL, 256);

    FILE* f = fopen("truncation_bug_demo.txt", "w");
    if (!f) { perror("truncation_bug_demo.txt"); return 1; }

    fprintf(f, "# SHRINCS Truncation Bug Demo\n");
    fprintf(f, "# Shows that only the first 32 (or 16) bytes of the message are hashed.\n");
    fprintf(f, "# Corruption before byte 32 - expected Fail.\n");
    fprintf(f, "# Corruption after  byte 32 - expected Fail, but the result is Pass.\n");

    int count = 0;

    static const size_t MLENS[] = { 64, 80, 96, 112, 128 };
    static const int N_MLENS = sizeof(MLENS) / sizeof(MLENS[0]);

    for (int mi = 0; mi < N_MLENS; ++mi)
    {
        size_t mlen = MLENS[mi];

        unsigned char seed[3*N];
        randombytes(seed, 3*N);

        std::vector<unsigned char> msg = std::vector<unsigned char>(mlen);
        randombytes(msg.data(), mlen);

        {
            PublicKey pk; SecretKey sk; State st;
            keygen(seed, pk, sk, st);
            unsigned char* sig = shrincs_sign_stateful(msg, sk, st);
            uint32_t slen = N + WOTS_SIGN_LEN + N;

            uint32_t off_before; unsigned char mask_before;
            random_offset_in(0, 32, off_before, mask_before);
            unsigned char* bad_before_ptr = corrupt_at(msg.data(), mlen, off_before, mask_before);
            std::vector<unsigned char> bad_before = std::vector<unsigned char>(bad_before_ptr, bad_before_ptr + mlen);

            bool ok_before = false;
            try { ok_before = shrincs_verify(bad_before, sig, slen, pk); }
            catch (...) {}

            char lbl[128];
            snprintf(lbl, sizeof(lbl),
                     "stateful q = 1 corrupt before byte32 mlen=%zu", mlen);
            write_record(f, count++, lbl, seed, mlen, msg.data(), pk, sig, slen,
                         bad_before.data(), off_before, mask_before, ok_before);
            if (ok_before)
                fprintf(stderr, "Unexpected Pass: corruption before byte 32 was ignored.\n");

            uint32_t off_after; unsigned char mask_after;
            random_offset_in(32, mlen, off_after, mask_after);
            unsigned char* bad_after_ptr = corrupt_at(msg.data(), mlen, off_after, mask_after);
            std::vector<unsigned char> bad_after = std::vector<unsigned char>(bad_after_ptr, bad_after_ptr + mlen);

            bool ok_after = false;
            try { ok_after = shrincs_verify(bad_after, sig, slen, pk); }
            catch (...) {}

            snprintf(lbl, sizeof(lbl),
                     "stateful q = 1 corrupt after byte32 mlen=%zu", mlen);
            write_record(f, count++, lbl, seed, mlen, msg.data(), pk, sig, slen,
                         bad_after.data(), off_after, mask_after, ok_after);
            if (ok_after)
                fprintf(stderr,
                        "Bug confirmation: stateful corruption at byte=%u (after 32) "
                        "was not detected. mlen=%zu\n", off_after, mlen);

            delete[] sig;
        }

        {
            PublicKey pk; SecretKey sk; State st;
            keygen(seed, pk, sk, st);
            unsigned char* sig = shrincs_sign_stateless(msg, sk);

            uint32_t off_before; unsigned char mask_before;
            random_offset_in(0, 32, off_before, mask_before);
            unsigned char* bad_before_ptr = corrupt_at(msg.data(), mlen, off_before, mask_before);
            std::vector<unsigned char> bad_before = std::vector<unsigned char>(bad_before_ptr, bad_before_ptr + mlen);

            bool ok_before = false;
            try { ok_before = shrincs_verify(bad_before, sig, SL_SIZE, pk); }
            catch (...) {}

            char lbl[128];
            snprintf(lbl, sizeof(lbl),
                     "stateless corrupt before byte32 mlen=%zu", mlen);
            write_record(f, count++, lbl, seed, mlen, msg.data(), pk, sig, SL_SIZE,
                         bad_before.data(), off_before, mask_before, ok_before);
            if (ok_before)
                fprintf(stderr, "Unexpected Pass: corruption before byte 32 was ignored.\n");

            uint32_t off_after; unsigned char mask_after;
            random_offset_in(32, mlen, off_after, mask_after);
            unsigned char* bad_after_ptr = corrupt_at(msg.data(), mlen, off_after, mask_after);
            std::vector<unsigned char> bad_after = std::vector<unsigned char>(bad_after_ptr, bad_after_ptr + mlen);

            bool ok_after = false;
            try { ok_after = shrincs_verify(bad_after, sig, SL_SIZE, pk); }
            catch (...) {}

            snprintf(lbl, sizeof(lbl),
                     "stateless corrupt after byte32 mlen=%zu", mlen);
            write_record(f, count++, lbl, seed, mlen, msg.data(), pk, sig, SL_SIZE,
                         bad_after.data(), off_after, mask_after, ok_after);
            if (ok_after)
                fprintf(stderr,
                        "Bug confirmation: stateless corruption at byte=%u (after 32) "
                        "was not detected! mlen=%zu\n", off_after, mlen);

            delete[] sig;
        }
    }
    
    return 0;
}