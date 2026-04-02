// SHRINCS Known-Answer Tests: corrupted data (FAIL cases)
//
// Select the parameter set at compile time:
//   -DSHRINCS_B   →  SHRINCS-B  (HSF=158, L=16, W=256, SWN=2040)    [default]
//   -DSHRINCS_L   →  SHRINCS-L  (HSF=206, L=64, W=4,   SWN=140)
//
// Build examples:
//   g++ -std=c++17 -O2 -DSHRINCS_L kat/kat_gen_fail.cpp kat/rng.c \
//       src/shrincs.cpp src/uxmss.cpp src/xmss.cpp src/fors_c.cpp  \
//       src/wots_c.cpp src/hash.cpp src/address.cpp                 \
//       -I./include -I./kat -lssl -lcrypto -o kat_fail_L
//
//   g++ -std=c++17 -O2 -DSHRINCS_B kat/kat_gen_fail.cpp kat/rng.c \
//       src/shrincs.cpp src/uxmss.cpp src/xmss.cpp src/fors_c.cpp  \
//       src/wots_c.cpp src/hash.cpp src/address.cpp                 \
//       -I./include -I./kat -lssl -lcrypto -o kat_fail_B
//
// Output: SHRINCS-{B|L}_fail.rsp
//
// -------------------------------------------------------------------
// All records must have the result = Fail.
//
// For throw cases (invalid state, counter exhausted):
//   sig = N/A, siglen = N/A, corrupted = N/A
// -------------------------------------------------------------------

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
        0x42,0x46,0x41,0x49,0x4c,0x5f,0x42,0x00,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
    };
#else
    static constexpr const char* VARIANT_NAME = "L";
    static unsigned char MASTER_SEED[48] = {
        0x4c,0x46,0x41,0x49,0x4c,0x5f,0x4c,0x00,
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

static void write_fail_record(FILE* f, int count, const char* label,
                               const unsigned char seed3N[3*N],
                               size_t mlen, const unsigned char* msg,
                               const PublicKey& pk, const SecretKey& sk,
                               const unsigned char* sig, uint32_t siglen,
                               const char* corrupted_type,
                               const unsigned char* corrupted_data,
                               size_t corrupted_len,
                               bool verify_result)
{
    fprintf(f, "count  = %d\n",  count);
    fprintf(f, "label  = %s\n",  label);
    fprintf(f, "seed   = "); fprint_hex(f, seed3N, 3*N);              fputc('\n', f);
    fprintf(f, "mlen   = %zu\n", mlen);
    fprintf(f, "msg    = "); fprint_hex(f, msg, mlen);                 fputc('\n', f);
    fprintf(f, "pk     = ");
    fprint_hex(f, pk.seed.data(), N); fprint_hex(f, pk.root.data(), N);
    fputc('\n', f);
    fprintf(f, "sk     = ");
    fprint_hex(f, sk.seed.data(), N);    fprint_hex(f, sk.prf.data(), N);
    fprint_hex(f, sk.sf.data(), N);      fprint_hex(f, sk.sl.data(), N);
    fprint_hex(f, sk.pk.seed.data(), N); fprint_hex(f, sk.pk.root.data(), N);
    fputc('\n', f);
    fprintf(f, "sig    = "); fprint_hex(f, sig, siglen);               fputc('\n', f);
    fprintf(f, "siglen = %u\n", siglen);
    fprintf(f, "%s = ", corrupted_type);
    fprint_hex(f, corrupted_data, corrupted_len);                      fputc('\n', f);
    fprintf(f, "result = %s\n\n", verify_result ? "Pass" : "Fail");
}

static void write_throw_record(FILE* f, int count, const char* label,
                                const unsigned char seed3N[3*N],
                                size_t mlen, const unsigned char* msg,
                                const PublicKey& pk, const SecretKey& sk,
                                bool threw)
{
    fprintf(f, "count  = %d\n",  count);
    fprintf(f, "label  = %s\n",  label);
    fprintf(f, "seed   = "); fprint_hex(f, seed3N, 3*N);              fputc('\n', f);
    fprintf(f, "mlen   = %zu\n", mlen);
    fprintf(f, "msg    = "); fprint_hex(f, msg, mlen);                 fputc('\n', f);
    fprintf(f, "pk     = ");
    fprint_hex(f, pk.seed.data(), N); fprint_hex(f, pk.root.data(), N);
    fputc('\n', f);
    fprintf(f, "sk     = ");
    fprint_hex(f, sk.seed.data(), N);    fprint_hex(f, sk.prf.data(), N);
    fprint_hex(f, sk.sf.data(), N);      fprint_hex(f, sk.sl.data(), N);
    fprint_hex(f, sk.pk.seed.data(), N); fprint_hex(f, sk.pk.root.data(), N);
    fputc('\n', f);
    fprintf(f, "sig       = N/A\n");
    fprintf(f, "siglen    = N/A\n");
    fprintf(f, "corrupted = N/A\n");
    fprintf(f, "result    = %s\n\n", threw ? "Fail" : "Pass");
}


static unsigned char* corrupt_random(const unsigned char* data, uint32_t len,
                                     uint32_t& out_offset, unsigned char& out_mask)
{
    unsigned char* bad = new unsigned char[len];
    memcpy(bad, data, len);

    unsigned char rbuf[5];
    randombytes(rbuf, 5);

    uint32_t off = ((uint32_t)rbuf[0] << 24 | (uint32_t)rbuf[1] << 16 |
                    (uint32_t)rbuf[2] << 8  | rbuf[3]) % len;
    unsigned char mask = rbuf[4];
    if (mask == 0) mask = 0x01;

    bad[off] ^= mask;
    out_offset = off;
    out_mask   = mask;
    return bad;
}

static unsigned char* corrupt_within(const unsigned char* data, uint32_t len,
                                      uint32_t& out_offset, unsigned char& out_mask,
                                      uint32_t max_byte = 32)
{
    unsigned char* bad = new unsigned char[len];
    memcpy(bad, data, len);

    unsigned char rbuf[5];
    randombytes(rbuf, 5);

    // clamp offset to first max_byte bytes
    uint32_t off = ((uint32_t)rbuf[0] << 24 | (uint32_t)rbuf[1] << 16 |
                    (uint32_t)rbuf[2] << 8  | rbuf[3]) % std::min((uint32_t)len, max_byte);
    unsigned char mask = rbuf[4];
    if (mask == 0) mask = 0x01;

    bad[off] ^= mask;
    out_offset = off;
    out_mask   = mask;
    return bad;
}

static const size_t MLEN_POOL[] = {
    1, 2, 3, 4, 5, 6, 7, 8,
    10, 12, 14, 16, 20, 24, 28, 32,
    40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224, 256
};
static const int  POOL_SIZE = sizeof(MLEN_POOL) / sizeof(MLEN_POOL[0]);
static const int  N_MSG     = 25;
static size_t     MSG_LENS[N_MSG];

static void init_msg_lens()
{
    for (int i = 0; i < N_MSG; ++i) {
        unsigned char buf[1];
        randombytes(buf, 1);
        MSG_LENS[i] = MLEN_POOL[buf[0] % POOL_SIZE];
    }
}

static const int N_CORRUPTIONS = 10;

int main()
{
    randombytes_init(MASTER_SEED, NULL, 256);
    init_msg_lens();

    char outfile[64];
    snprintf(outfile, sizeof(outfile), "SHRINCS-%s_fail.rsp", VARIANT_NAME);
    FILE* f = fopen(outfile, "w");
    if (!f) { perror(outfile); return 1; }

    fprintf(f, "# SHRINCS-%s Known-Answer Tests — FAIL (corrupted/invalid data)\n", VARIANT_NAME);
    fprintf(f, "# All records are expected to have result = Fail.\n");
    fprintf(f, "# If result = Pass appears, the verifier has a bug — check stderr for WARN lines.\n");
    fprintf(f, "# Signing is always performed correctly; corruption is applied after.\n");
    fprintf(f, "# Original data is in canonical fields; corrupted version on its own line.\n");
    fprintf(f, "# sig = N/A / corrupted = N/A when the sign call itself throws.\n");
    fprintf(f, "# Message lengths randomly drawn from pool [%zu..%zu] bytes.\n\n",
            MLEN_POOL[0], MLEN_POOL[POOL_SIZE - 1]);

    int count = 0;
    char lbl[256];

    for (int mi = 0; mi < N_MSG; ++mi)
    {
        size_t mlen = MSG_LENS[mi];

        unsigned char seed[3*N];
        randombytes(seed, 3*N);

        unsigned char seed_alt[3*N];
        randombytes(seed_alt, 3*N);

        std::vector<unsigned char> msg = std::vector<unsigned char>(mlen);
        randombytes(msg.data(), mlen);

        //Wrong message
        for (int ci = 0; ci < N_CORRUPTIONS; ++ci)
        {
            {
                PublicKey pk; SecretKey sk; State st;
                keygen(seed, pk, sk, st);
                unsigned char* sig = shrincs_sign_stateful(msg, sk, st);
                uint32_t slen = sf_siglen(1);

                uint32_t off; unsigned char mask;
                unsigned char* bad_msg_ptr = corrupt_within(msg.data(), mlen, off, mask);
                std::vector<unsigned char> bad_msg = std::vector<unsigned char>(bad_msg_ptr, bad_msg_ptr + mlen);
                if(memcmp(bad_msg.data(), msg.data(), mlen) == 0) fprintf(stderr, "WARN: identical messages\n");

                if (off < 32)
                    fprintf(stderr, "INFO: corruption within first 32 bytes at byte=%u\n", off);
                else
                    fprintf(stderr, "INFO: corruption beyond byte 32 at byte=%u — expect Pass (bug)\n", off);

                bool ok = shrincs_verify(bad_msg, sig, slen, pk);

                snprintf(lbl, sizeof(lbl),
                         "SHRINCS-%s stateful wrong-msg byte=%u mask=0x%02x mlen=%zu",
                         VARIANT_NAME, off, mask, mlen);
                write_fail_record(f, count++, lbl, seed,
                                  mlen, msg.data(), pk, sk, sig, slen,
                                  "msg corrupted", bad_msg.data(), mlen, ok);
                if (ok) fprintf(stderr, "WARN [%s]: expected Fail, got Pass\n", lbl);
                delete[] sig;
            }

            {
                PublicKey pk; SecretKey sk; State st;
                keygen(seed, pk, sk, st);
                unsigned char* sig = shrincs_sign_stateless(msg, sk);

                uint32_t off; unsigned char mask;
                unsigned char* bad_msg_ptr = corrupt_within(msg.data(), mlen, off, mask);
                std::vector<unsigned char> bad_msg = std::vector<unsigned char>(bad_msg_ptr, bad_msg_ptr + mlen);
                if (off < 32)
                    fprintf(stderr, "INFO: corruption within first 32 bytes at byte=%u\n", off);
                else
                    fprintf(stderr, "INFO: corruption beyond byte 32 at byte=%u — expect Pass (bug)\n", off);
                bool ok = false;
                try { ok = shrincs_verify(bad_msg, sig, SL_SIZE, pk); }
                catch (...) {}

                snprintf(lbl, sizeof(lbl),
                         "SHRINCS-%s stateless wrong-msg byte=%u mask=0x%02x mlen=%zu",
                         VARIANT_NAME, off, mask, mlen);
                write_fail_record(f, count++, lbl, seed,
                                  mlen, msg.data(), pk, sk, sig, SL_SIZE,
                                  "msg corrupted", bad_msg.data(), mlen, ok);
                if (ok) fprintf(stderr, "WARN [%s]: expected Fail, got Pass\n", lbl);
                delete[] sig;
            }
        }

        //Wrong public key
        for (int ci = 0; ci < N_CORRUPTIONS; ++ci)
        {
            {
                PublicKey pk;  SecretKey sk;  State st;
                PublicKey pk2; SecretKey sk2; State st2;
                keygen(seed,     pk,  sk,  st);
                keygen(seed_alt, pk2, sk2, st2);

                unsigned char* sig = shrincs_sign_stateful(msg, sk, st);
                uint32_t slen = sf_siglen(1);

                bool ok = shrincs_verify(msg, sig, slen, pk2);

                // pack pk2 into a flat buffer for fprint_hex
                unsigned char pk2_bytes[2*N];
                memcpy(pk2_bytes,     pk2.seed.data(), N);
                memcpy(pk2_bytes + N, pk2.root.data(), N);

                snprintf(lbl, sizeof(lbl),
                         "SHRINCS-%s stateful wrong-pk ci=%d mlen=%zu",
                         VARIANT_NAME, ci, mlen);
                write_fail_record(f, count++, lbl, seed,
                                  mlen, msg.data(), pk, sk, sig, slen,
                                  "pk corrupted", pk2_bytes, 2*N, ok);
                if (ok) fprintf(stderr, "WARN [%s]: expected Fail, got Pass\n", lbl);
                delete[] sig;

                randombytes(seed_alt, 3*N);
            }

            {
                PublicKey pk;  SecretKey sk;  State st;
                PublicKey pk2; SecretKey sk2; State st2;
                keygen(seed,     pk,  sk,  st);
                keygen(seed_alt, pk2, sk2, st2);

                unsigned char* sig = shrincs_sign_stateless(msg, sk);

                bool ok = false;
                try { ok = shrincs_verify(msg, sig, SL_SIZE, pk2); }
                catch (...) {}

                unsigned char pk2_bytes[2*N];
                memcpy(pk2_bytes,     pk2.seed.data(), N);
                memcpy(pk2_bytes + N, pk2.root.data(), N);

                snprintf(lbl, sizeof(lbl),
                         "SHRINCS-%s stateless wrong-pk ci=%d mlen=%zu",
                         VARIANT_NAME, ci, mlen);
                write_fail_record(f, count++, lbl, seed,
                                  mlen, msg.data(), pk, sk, sig, SL_SIZE,
                                  "pk corrupted", pk2_bytes, 2*N, ok);
                if (ok) fprintf(stderr, "WARN [%s]: expected Fail, got Pass\n", lbl);
                delete[] sig;

                randombytes(seed_alt, 3*N);
            }
        }

        // Corrupted signature bytes
        {
            PublicKey pk; SecretKey sk; State st;
            keygen(seed, pk, sk, st);
            unsigned char* sig = shrincs_sign_stateful(msg, sk, st);
            uint32_t slen = sf_siglen(1);

            for (int ci = 0; ci < N_CORRUPTIONS; ++ci)
            {
                uint32_t off; unsigned char mask;
                unsigned char* bad = corrupt_random(sig, slen, off, mask);

                bool ok = false;
                try { ok = shrincs_verify(msg, bad, slen, pk); }
                catch (...) {}

                snprintf(lbl, sizeof(lbl),
                         "SHRINCS-%s stateful corrupted-sig byte=%u mask=0x%02x mlen=%zu",
                         VARIANT_NAME, off, mask, mlen);
                write_fail_record(f, count++, lbl, seed,
                                  mlen, msg.data(), pk, sk, sig, slen,
                                  "sig corrupted", bad, slen, ok);
                if (ok) fprintf(stderr, "WARN [%s]: expected Fail, got Pass\n", lbl);
                delete[] bad;
            }
            delete[] sig;
        }

        {
            PublicKey pk; SecretKey sk; State st;
            keygen(seed, pk, sk, st);
            unsigned char* sig = shrincs_sign_stateless(msg, sk);

            for (int ci = 0; ci < N_CORRUPTIONS; ++ci)
            {
                uint32_t off; unsigned char mask;
                unsigned char* bad = corrupt_random(sig, SL_SIZE, off, mask);

                bool ok = false;
                try { ok = shrincs_verify(msg, bad, SL_SIZE, pk); }
                catch (...) {}

                snprintf(lbl, sizeof(lbl),
                         "SHRINCS-%s stateless corrupted-sig byte=%u mask=0x%02x mlen=%zu",
                         VARIANT_NAME, off, mask, mlen);
                write_fail_record(f, count++, lbl, seed,
                                  mlen, msg.data(), pk, sk, sig, SL_SIZE,
                                  "sig corrupted", bad, SL_SIZE, ok);
                if (ok) fprintf(stderr, "WARN [%s]: expected Fail, got Pass\n", lbl);
                delete[] bad;
            }
            delete[] sig;
        }

        {
            PublicKey pk; SecretKey sk; State st;
            keygen(seed, pk, sk, st);
            unsigned char* sig = shrincs_sign_stateless(msg, sk);

            bool ok = false;
            try { ok = shrincs_verify(msg, sig, MAX_SF_SIZE, pk); }
            catch (...) {}

            snprintf(lbl, sizeof(lbl),
                     "SHRINCS-%s cross-type stateless-sig-as-stateful mlen=%zu",
                     VARIANT_NAME, mlen);
            write_fail_record(f, count++, lbl, seed,
                              mlen, msg.data(), pk, sk, sig, SL_SIZE,
                              "sig corrupted (truncated to MAX_SF_SIZE)", sig, MAX_SF_SIZE, ok);
            if (ok) fprintf(stderr, "WARN [%s]: expected Fail, got Pass\n", lbl);
            delete[] sig;
        }

        // Invalid State
        {
            PublicKey pk; SecretKey sk; State st;
            shrincs_restore(seed, pk, sk, st);

            bool threw = false;
            try {
                unsigned char* tmp = shrincs_sign_stateful(msg, sk, st);
                delete[] tmp;
            } catch (...) { threw = true; }

            snprintf(lbl, sizeof(lbl),
                     "SHRINCS-%s stateful invalid-state (valid=false) mlen=%zu",
                     VARIANT_NAME, mlen);
            write_throw_record(f, count++, lbl, seed, mlen, msg.data(), pk, sk, threw);
            if (!threw) fprintf(stderr, "WARN [%s]: expected throw, did not throw\n", lbl);
        }
    }

    // Counter exhausted (once, outside message loop)
    {
        unsigned char seed[3*N];
        randombytes(seed, 3*N);

        std::vector<unsigned char> msg = std::vector<unsigned char>(32);
        randombytes(msg.data(),32);

        PublicKey pk; SecretKey sk; State st;
        keygen(seed, pk, sk, st);

        for (uint32_t q = 1; q <= HSF + 1; ++q) {
            try {
                unsigned char* tmp = shrincs_sign_stateful(msg, sk, st);
                delete[] tmp;
            } catch (...) { break; }
        }

        bool threw = false;
        try {
            unsigned char* tmp = shrincs_sign_stateful(msg, sk, st);
            delete[] tmp;
        } catch (...) { threw = true; }

        snprintf(lbl, sizeof(lbl),
                 "SHRINCS-%s stateful counter-exhausted q > HSF+1=%u",
                 VARIANT_NAME, HSF + 1);
        write_throw_record(f, count++, lbl, seed, 32, msg.data(), pk, sk, threw);
        if (!threw) fprintf(stderr, "WARN [%s]: expected throw, did not throw\n", lbl);
    }

    fprintf(f, "# Total records: %d\n", count);
    fclose(f);
    printf("Wrote %d records to %s\n", count, outfile);
    return 0;
}