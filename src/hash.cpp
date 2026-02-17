#include "hash.h"

namespace HASH 
{
    SHA256_CTX sha256_add_to_ctx(const SHA256_CTX& base_ctx, const unsigned char* data, size_t len) 
    {
        SHA256_CTX working_ctx = base_ctx;
        SHA256_Update(&working_ctx, data, len);
        return working_ctx;
    }

    void sha256_finalize(const SHA256_CTX& base_ctx, unsigned char* out) 
    {
        SHA256_CTX working_ctx = base_ctx;
        unsigned char full_hash[SHA256_DIGEST_LENGTH];

        SHA256_Final(full_hash, &working_ctx);

        memcpy(out, full_hash, N);
    }

    void sha256_finalize_32(const SHA256_CTX& base_ctx, unsigned char* out)
    {
        SHA256_CTX working_ctx = base_ctx;
        unsigned char full_hash[SHA256_DIGEST_LENGTH];

        SHA256_Final(full_hash, &working_ctx);

        memcpy(out, full_hash, 32);
    }

    void prf_msg(const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* opt_rand, const unsigned char* message, uint32_t message_len, bool is_ctr, uint32_t ctr, uint32_t mask_len, unsigned char* out)
    {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        ctx = sha256_add_to_ctx(ctx, sk_prf, N);
        ctx = sha256_add_to_ctx(ctx, pk_seed, N);
        ctx = sha256_add_to_ctx(ctx, opt_rand, N);
        ctx = sha256_add_to_ctx(ctx, message, message_len);
        if (is_ctr)
        {
            ctx = sha256_add_to_ctx(ctx, reinterpret_cast<const unsigned char*>(&ctr), 4);
        }

        for (uint32_t i = 0; i < ceil((mask_len + 31) / 32); i++)
        {
            uint32_t ctr_be = htonl(i);
            auto ctx_ = sha256_add_to_ctx(ctx, reinterpret_cast<const unsigned char*>(&ctr_be), 4);
            unsigned char hash[32];
            sha256_finalize_32(ctx_, hash);

            memcpy(out + i * 32, hash, std::min(mask_len - i * 32, 32u));
        }
    }
}