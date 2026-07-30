#include "hash.h"

namespace HASH 
{
    void xor_array(const unsigned char* data1, const unsigned char* data2, unsigned char* out, uint32_t size) {
        for (uint32_t i = 0; i < size; i++)
        {
            out[i] = data1[i] ^ data2[i];
        }
    }

    void sha256_add_to_ctx(CSHA256& base_ctx, const unsigned char* data, size_t len) 
    {
        base_ctx.Write(data, len);
    }

    void sha256_finalize(CSHA256& base_ctx, unsigned char* out) 
    {
        unsigned char full_hash[32];

        base_ctx.Finalize(full_hash);

        memcpy(out, full_hash, N);
    }

    void sha256_finalize_32(CSHA256& base_ctx, unsigned char* out)
    {
        unsigned char full_hash[32];

        base_ctx.Finalize(full_hash);

        memcpy(out, full_hash, 32);
    }

    void t_sl(CSHA256& base_ctx, unsigned char* adrs, const unsigned char* m_l, unsigned char* out)
    {
        CSHA256 ctx = base_ctx;
        sha256_add_to_ctx(ctx, adrs, 22);
        sha256_add_to_ctx(ctx, m_l, WOTS_TW_CHAINS_SIZE);
        sha256_finalize(ctx, out);
    }

    void t_sf(CSHA256& base_ctx, unsigned char* adrs, const unsigned char* m_l, unsigned char* out)
    {
        CSHA256 ctx = base_ctx;
        sha256_add_to_ctx(ctx, adrs, 22);
        sha256_add_to_ctx(ctx, m_l, WOTS_C_CHAINS_SIZE);
        sha256_finalize(ctx, out);
    }

    void t_k(CSHA256& base_ctx, unsigned char* adrs, const unsigned char* m_k, unsigned char* out)
    {
        CSHA256 ctx = base_ctx;
        sha256_add_to_ctx(ctx, adrs, 22);
        sha256_add_to_ctx(ctx, m_k, SPHX_FORS_COUNT << 4);
        sha256_finalize(ctx, out);
    }

    void f(CSHA256& base_ctx, unsigned char* adrs, const unsigned char* m_1, unsigned char* out)
    {
        CSHA256 ctx = base_ctx;
        sha256_add_to_ctx(ctx, adrs, 22);
        sha256_add_to_ctx(ctx, m_1, N);
        sha256_finalize(ctx, out);
    }

    void h(CSHA256& base_ctx, unsigned char* adrs, const unsigned char* m_2, unsigned char* out)
    {
        CSHA256 ctx = base_ctx;
        sha256_add_to_ctx(ctx, adrs, 22);
        sha256_add_to_ctx(ctx, m_2, N << 1);
        sha256_finalize(ctx, out);
    }

    void h_grind(CSHA256& base_ctx, unsigned char* adrs, const unsigned char* digest, uint32_t counter, unsigned char* out)
    {
        // assert counter <= 0xFFFF

        CSHA256 ctx = base_ctx;
        sha256_add_to_ctx(ctx, adrs, 10);
        sha256_add_to_ctx(ctx, digest, N << 1);
        sha256_add_to_ctx(ctx, zeros, 4);

        unsigned char counter_be[2] = {
            static_cast<unsigned char>(counter >> 8),
            static_cast<unsigned char>(counter)
        };
        sha256_add_to_ctx(ctx, counter_be, 2);
        sha256_finalize(ctx, out);
    }

    void hmac_sha256(const unsigned char* key, uint8_t key_len, const unsigned char* message, uint64_t m_len, unsigned char* out)
    {
        // assert key_len <= 64
        unsigned char padded_key[64];
        memcpy(padded_key, key, key_len);
        memcpy(padded_key + key_len, zeros, 64 - key_len);

        unsigned char tmp[64];
        xor_array(padded_key, const_0x36, tmp, 64);

        unsigned char inner[32];
        CSHA256 ctx1;
        sha256_add_to_ctx(ctx1, tmp, 64);
        sha256_add_to_ctx(ctx1, message, m_len);
        sha256_finalize_32(ctx1, inner);

        xor_array(padded_key, const_0x5c, tmp, 64);
        CSHA256 ctx2;
        sha256_add_to_ctx(ctx2, tmp, 64);
        sha256_add_to_ctx(ctx2, inner, 32);
        sha256_finalize_32(ctx2, out);
    }

    void prf(CSHA256& base_ctx, const unsigned char* sk_seed, unsigned char* adrs, unsigned char* out)
    {
        CSHA256 ctx = base_ctx;
        sha256_add_to_ctx(ctx, adrs, 22);
        sha256_add_to_ctx(ctx, sk_seed, N);
        sha256_finalize(ctx, out);
    }

    void prf_msg_sl(const unsigned char* sk_prf, const unsigned char* opt_rand, const unsigned char* message, uint32_t m_len, unsigned char* out)
    {
        unsigned char* h_input = new unsigned char[m_len + N];
        memcpy(h_input, opt_rand, N);
        memcpy(h_input + N, message, m_len);

        unsigned char tmp[32];
        hmac_sha256(sk_prf, N, h_input, m_len + N, tmp);
        memcpy(out, tmp, N);

        delete[] h_input;
    }

    void prf_msg_sf(const unsigned char* sk_prf, const unsigned char* pk_seed, unsigned char* adrs, const unsigned char* message, uint32_t m_len, unsigned char* out)
    {
        unsigned char h_key[64];
        memcpy(h_key, sk_prf, N);
        memcpy(h_key + N, const_0xff, 48);

        unsigned char* h_input = new unsigned char[m_len + N + 9];
        memcpy(h_input, pk_seed, N);
        memcpy(h_input + N, adrs, 9);
        memcpy(h_input + N + 9, message, m_len);

        unsigned char tmp[32];
        hmac_sha256(h_key, 64, h_input, m_len + N + 9, tmp);
        memcpy(out, tmp, N);

        delete[] h_input;
    }

    void h_msg_sl(const unsigned char* r, const unsigned char* pk_seed, const unsigned char* sl_root, const unsigned char* message, uint32_t m_len, unsigned char* out)
    {
        unsigned char tmp[32];
        CSHA256 ctx_i;
        sha256_add_to_ctx(ctx_i, r, N);
        sha256_add_to_ctx(ctx_i, pk_seed, N);
        sha256_add_to_ctx(ctx_i, sl_root, N);
        sha256_add_to_ctx(ctx_i, message, m_len);
        sha256_finalize_32(ctx_i, tmp);

        CSHA256 ctx_e;
        sha256_add_to_ctx(ctx_e, r, N);
        sha256_add_to_ctx(ctx_e, pk_seed, N);
        sha256_add_to_ctx(ctx_e, tmp, 32);
        sha256_add_to_ctx(ctx_e, zeros, 4);
        sha256_finalize_32(ctx_e, out);
    }

    void h_msg_sf(const unsigned char* r, const unsigned char* pk_seed, const unsigned char* sf_root, unsigned char* adrs, const unsigned char* message, uint32_t m_len, unsigned char* out)
    {
        unsigned char tmp[32];
        CSHA256 ctx_i;
        sha256_add_to_ctx(ctx_i, r, N);
        sha256_add_to_ctx(ctx_i, pk_seed, N);
        sha256_add_to_ctx(ctx_i, sf_root, N);
        sha256_add_to_ctx(ctx_i, adrs, 9);
        sha256_add_to_ctx(ctx_i, message, m_len);
        sha256_finalize_32(ctx_i, tmp);

        CSHA256 ctx_e;
        sha256_add_to_ctx(ctx_e, r, N);
        sha256_add_to_ctx(ctx_e, pk_seed, N);
        sha256_add_to_ctx(ctx_e, adrs, 9);
        sha256_add_to_ctx(ctx_e, tmp, 32);
        sha256_finalize_32(ctx_e, out);
    }
}