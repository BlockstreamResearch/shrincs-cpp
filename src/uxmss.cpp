#include "uxmss.h"

namespace UXMSS 
{
    unsigned char* uxmss_treehash(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t level)
    {
        auto left = wots_pk_gen(sk_seed, hash_ctx, adrs, level + 1, true);

        unsigned char* right;
        if (level == HSF - 1)
        {
            right = wots_pk_gen(sk_seed, hash_ctx, adrs, HSF + 1, true);
        }
        else
        {
            right = uxmss_treehash(sk_seed, hash_ctx, adrs, level + 1);
        }

        setTypeAndClear(adrs, SF_TREE);
        setTreeHeight(adrs, HSF - level);
        setTreeIndex(adrs, 0);

        auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, left, N);
        ctx = sha256_add_to_ctx(ctx, right, N);

        unsigned char* res = new unsigned char[N];
        sha256_finalize(ctx, res);

        delete[] left;
        delete[] right;

        return res;
    }

    unsigned char* uxmss_root(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs)
    {
        setLayerAddress(adrs, 0);
        setTreeAddress(adrs, 0, 0);
        return uxmss_treehash(sk_seed, hash_ctx, adrs, 0);
    }

    unsigned char* uxmss_auth_path(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t q)
    {
        unsigned char* auth = new unsigned char[(q > HSF ? q - 1 : q) * N];

        setLayerAddress(adrs, 0);
        setTreeAddress(adrs, 0, 0);
        
        unsigned char* tmp;
        if (q <= HSF)
        {
            if (q == HSF) 
            {
                tmp = wots_pk_gen(sk_seed, hash_ctx, adrs, HSF + 1, true);
                memcpy(auth, tmp, N);
            }
            else
            {
                tmp = uxmss_treehash(sk_seed, hash_ctx, adrs, q);
                memcpy(auth, tmp, N);
            }
            delete[] tmp;

            for (uint32_t i = 1; i < q; i++)
            {
                tmp = wots_pk_gen(sk_seed, hash_ctx, adrs, q - i, true);
                memcpy(auth + N*i, tmp, N);
                delete[] tmp;
            }
        }
        else {
            for (uint32_t i = 0; i < HSF; i++)
            {
                tmp = wots_pk_gen(sk_seed, hash_ctx, adrs, HSF - i, true);
                memcpy(auth + N*i, tmp, N);
                delete[] tmp;
            }
        }

        return auth;
    }

    unsigned char* uxmss_pk_from_sig(const unsigned char* wots_sig, const unsigned char* auth, const unsigned char* message, uint32_t message_len, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t q)
    {
        setLayerAddress(adrs, 0);
        setTreeAddress(adrs, 0, 0);
        auto node = wots_pk_from_sig(wots_sig, message, message_len, pk_root, hash_ctx, adrs, q, true, false);

        setTypeAndClear(adrs, SF_TREE);
        if (q <= HSF) 
        {
            setTreeHeight(adrs, HSF - (q - 1));
            setTreeIndex(adrs, 0);

            auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, node, N);
            ctx = sha256_add_to_ctx(ctx, auth, N);

            sha256_finalize(ctx, node);

            for (uint32_t i = 1; i < q; i++)
            {
                setTreeHeight(adrs, HSF - (q - 1 - i));
                setTreeIndex(adrs, 0);

                ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
                ctx = sha256_add_to_ctx(ctx, auth + N*i, N);
                ctx = sha256_add_to_ctx(ctx, node, N);

                sha256_finalize(ctx, node);
            }
        }
        else 
        {
            for (uint32_t i = 0; i < HSF; i++)
            {
                setTreeHeight(adrs, i + 1);
                setTreeIndex(adrs, 0);

                auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
                ctx = sha256_add_to_ctx(ctx, auth + N*i, N);
                ctx = sha256_add_to_ctx(ctx, node, N);

                sha256_finalize(ctx, node);
            }
        }

        return node;
    }

    unsigned char* uxmss_sign(const unsigned char* message, uint32_t message_len, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t q)
    {
        setLayerAddress(adrs, 0);
        setTreeAddress(adrs, 0, 0);
        auto wots_sig = wots_sign(message, message_len, sk_seed, sk_prf, pk_seed, pk_root, hash_ctx, adrs, q, true, false);
        auto auth = uxmss_auth_path(sk_seed, hash_ctx, adrs, q);

        if (q > HSF)
        {
            q -= 1;
        }

        unsigned char* res = new unsigned char[WOTS_SIGN_LEN + q * N];
        memcpy(res, wots_sig, WOTS_SIGN_LEN);
        memcpy(res + WOTS_SIGN_LEN, auth, q * N);

        delete[] wots_sig;
        delete[] auth;
        return res;
    }
}