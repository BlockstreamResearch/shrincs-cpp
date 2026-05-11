#include "hash.h"

namespace HASH 
{
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

    void prf_msg(const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* opt_rand, const unsigned char* message, uint32_t message_len, bool is_ctr, uint32_t ctr, uint32_t mask_len, unsigned char* out)
    {
        CSHA256 ctx;

        sha256_add_to_ctx(ctx, sk_prf, N);
        sha256_add_to_ctx(ctx, pk_seed, N);
        sha256_add_to_ctx(ctx, opt_rand, N);
        if (is_ctr)
        {
            sha256_add_to_ctx(ctx, reinterpret_cast<const unsigned char*>(&ctr), 4);
        }
        sha256_add_to_ctx(ctx, message, message_len);

        unsigned char hash[32];
        uint32_t num_blocks = (mask_len + 31) / 32;

        for (uint32_t i = 0; i < num_blocks; i++)
        {
            CSHA256 ctx_ = ctx;
            uint32_t ctr_be = htonl(i);
            sha256_add_to_ctx(ctx_, reinterpret_cast<const unsigned char*>(&ctr_be), 4);
            sha256_finalize_32(ctx_, hash);

            memcpy(out + i * 32, hash, std::min(mask_len - i * 32, 32u));
        }
    }
}