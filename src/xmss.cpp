#include "xmss.h"

namespace XMSS 
{
    unsigned char* xmss_treehash(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t target_height, uint32_t start_idx)
    {
        if (target_height == 0) 
        {
            return wots_pk_gen(sk_seed, hash_ctx, adrs, start_idx, false);
        }

        auto left = xmss_treehash(sk_seed, hash_ctx, adrs, target_height - 1, start_idx);
        auto right = xmss_treehash(sk_seed, hash_ctx, adrs, target_height - 1, start_idx + pow(2, target_height - 1));

        setTypeAndClear(adrs, SL_TREE);
        setTreeHeight(adrs, target_height);
        setTreeIndex(adrs, start_idx >> target_height);

        auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, left, N);
        ctx = sha256_add_to_ctx(ctx, right, N);

        unsigned char* res = new unsigned char[N];
        sha256_finalize(ctx, res);

        delete[] left;
        delete[] right;

        return res;
    }

    unsigned char* xmss_root(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t h_prime)
    {
        return xmss_treehash(sk_seed, hash_ctx, adrs, h_prime, 0);
    }

    unsigned char* xmss_auth_path(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t h_prime, uint32_t idx)
    {
        unsigned char* auth = new unsigned char[h_prime * N];
        unsigned char* tmp;
        for (uint32_t i = 0; i < h_prime; i++)
        {
            uint32_t sibling_start = ((idx ^ (1 << i)) >> i) << i;
            tmp = xmss_treehash(sk_seed, hash_ctx, adrs, i, sibling_start);
            memcpy(auth + i*N, tmp, N);
            delete[] tmp;
        }
        
        return auth;
    }

    unsigned char* xmss_pk_from_sig(const unsigned char* wots_sig, const unsigned char* auth, const unsigned char* message, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t h_prime, uint32_t idx)
    {
        auto node = wots_pk_from_sig(wots_sig, message, N, pk_root, hash_ctx, adrs, idx, false, true);

        for (uint32_t i = 0; i < h_prime; i++)
        {
            setTypeAndClear(adrs, SL_TREE);
            setTreeHeight(adrs, i + 1);
            setTreeIndex(adrs, idx >> 1);
            unsigned char auth_node[N];
            memcpy(auth_node, auth + N*i, N);

            auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            if ((idx & 1) == 0)
            {
                ctx = sha256_add_to_ctx(ctx, node, N);
                ctx = sha256_add_to_ctx(ctx, auth_node, N);
            }
            else
            {
                ctx = sha256_add_to_ctx(ctx, auth_node, N);
                ctx = sha256_add_to_ctx(ctx, node, N);
            }

            sha256_finalize(ctx, node);
            idx >>= 1;
        }

        return node;
    }

    unsigned char* xmss_sign(const unsigned char* message, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t h_prime, uint32_t idx) 
    {
        unsigned char* sig = new unsigned char[XMSS_SIGN_LEN];

        auto wots_sig = wots_sign(message, N, sk_seed, sk_prf, pk_seed, pk_root, hash_ctx, adrs, idx, false, true);
        auto auth = xmss_auth_path(sk_seed, hash_ctx, adrs, h_prime, idx);
        
        memcpy(sig, wots_sig, WOTS_SIGN_LEN);
        memcpy(sig + WOTS_SIGN_LEN, auth, h_prime * N);

        delete[] wots_sig;
        delete[] auth;
        return sig;
    }
}