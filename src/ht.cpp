#include "ht.h"

namespace HT
{
    void hypertree_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, uint64_t tree_index, uint32_t leaf_index, unsigned char* out)
    {
        unsigned char adrs[22] = {0}, tmp[N];
        uint32_t offset = 0, leaf_mode = 1 << SPHX_XMSS_HEIGHT;

        memcpy(tmp, message, N);

        for (uint32_t i = 0; i < SPHX_LAYER_COUNT; i++)
        {
            setLayerAddress(adrs, i);
            setTreeAddress(adrs, tree_index);
            xmss_sign(tmp, sk_seed, hash_ctx, adrs, leaf_index, out + offset);
            if (i < SPHX_LAYER_COUNT - 1)
            {
                xmss_pk_from_sig(out + offset, tmp, hash_ctx, adrs, leaf_index, tmp);
                leaf_index = tree_index % leaf_mode;
                tree_index >>= SPHX_XMSS_HEIGHT;
            }
            offset += SPHX_XMSS_SIGNATURE_SIZE;
        }
    }

    bool hypertree_verify(const unsigned char* sig, const unsigned char* message, CSHA256& hash_ctx, uint64_t tree_index, uint32_t leaf_index, const unsigned char* sl_root)
    {
        unsigned char adrs[22] = {0}, tmp[N];
        uint32_t offset = 0, leaf_mode = 1 << SPHX_XMSS_HEIGHT;

        memcpy(tmp, message, N);

        for (uint32_t i = 0; i < SPHX_LAYER_COUNT; i++)
        {
            setLayerAddress(adrs, i);
            setTreeAddress(adrs, tree_index);
            xmss_pk_from_sig(sig + offset, tmp, hash_ctx, adrs, leaf_index, tmp);
            if (i < SPHX_LAYER_COUNT - 1)
            {
                leaf_index = tree_index % leaf_mode;
                tree_index >>= SPHX_XMSS_HEIGHT;
            }
            offset += SPHX_XMSS_SIGNATURE_SIZE;
        }

        return memcmp(sl_root, tmp, N) == 0;
    }
}