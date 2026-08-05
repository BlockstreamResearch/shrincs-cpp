#include "xmss.h"

namespace XMSS
{
    [[maybe_unused]] static const int PARALLEL_MIN_LEAVES = 16;

    static void xmss_leaves(const unsigned char* sk_seed, CSHA256& hash_ctx, const unsigned char* adrs, uint32_t node_idx, uint32_t node_height, unsigned char* out)
    {
        int count = 1 << node_height;
        uint32_t base = node_idx << node_height;

        #pragma omp parallel for schedule(static) if(count >= PARALLEL_MIN_LEAVES)
        for (int i = 0; i < count; i++)
        {
            unsigned char leaf_adrs[22];
            memcpy(leaf_adrs, adrs, 22);
            set_10_14(leaf_adrs, base + (uint32_t)i);

            wots_tw_pk_gen(sk_seed, hash_ctx, leaf_adrs, out + (size_t)i * N);
        }
    }

    void xmss_node(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t node_idx, uint32_t node_height, unsigned char* out)
    {
        if (!node_height)
        {
            set_10_14(adrs, node_idx);
            wots_tw_pk_gen(sk_seed, hash_ctx, adrs, out);
            return;
        }

        unsigned char nodes[(1u << SPHX_XMSS_HEIGHT) * N];
        xmss_leaves(sk_seed, hash_ctx, adrs, node_idx, node_height, nodes);

        setType(adrs, SL_XMSS_TREE);
        set_10_14(adrs, 0);

        uint32_t count = 1u << node_height;
        uint32_t base = node_idx << node_height;

        for (uint32_t level = 1; level <= node_height; level++)
        {
            count >>= 1;
            base >>= 1;

            for (uint32_t i = 0; i < count; i++)
            {
                set_14_18(adrs, level);
                set_18_22(adrs, base + i);

                h(hash_ctx, adrs, nodes + (size_t)(2 * i) * N, nodes + (size_t)i * N);
            }
        }

        memcpy(out, nodes, N);
    }

    void xmss_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t keypair_index, unsigned char* out)
    {
        unsigned char tree_adrs[22];
        memcpy(tree_adrs, adrs, 22);

        set_10_14(adrs, keypair_index);
        wots_tw_sign(message, sk_seed, hash_ctx, adrs, out);

        unsigned char nodes[(1u << SPHX_XMSS_HEIGHT) * N];
        xmss_leaves(sk_seed, hash_ctx, tree_adrs, 0, SPHX_XMSS_HEIGHT, nodes);

        setType(tree_adrs, SL_XMSS_TREE);
        set_10_14(tree_adrs, 0);

        uint32_t offset = WOTS_TW_CHAINS_SIZE;
        uint32_t count = 1u << SPHX_XMSS_HEIGHT;

        for (uint32_t level = 0; level < SPHX_XMSS_HEIGHT; level++)
        {
            memcpy(out + offset, nodes + (size_t)((keypair_index >> level) ^ 1) * N, N);
            offset += N;

            count >>= 1;
            for (uint32_t i = 0; i < count; i++)
            {
                set_14_18(tree_adrs, level + 1);
                set_18_22(tree_adrs, i);

                h(hash_ctx, tree_adrs, nodes + (size_t)(2 * i) * N, nodes + (size_t)i * N);
            }
        }
    }

    void xmss_pk_from_sig(const unsigned char* sig, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, uint32_t keypair_index, unsigned char* out)
    {
        unsigned char nodes[N << 1];
        set_10_14(adrs, keypair_index);
        wots_tw_pk_from_sig(sig, message, hash_ctx, adrs, out);

        setType(adrs, SL_XMSS_TREE);
        set_10_14(adrs, 0);

        uint32_t offset = WOTS_TW_CHAIN_COUNT * N;

        for (uint32_t i = 0; i < SPHX_XMSS_HEIGHT; i++)
        {
            set_14_18(adrs, i + 1);
            set_18_22(adrs, keypair_index >> (i + 1));

            if(((keypair_index >> i) & 1) == 1)
            {
                memcpy(nodes, sig + offset, N);
                memcpy(nodes + N, out, N);
            }
            else
            {
                memcpy(nodes, out, N);
                memcpy(nodes + N, sig + offset, N);
            }
            offset += N;

            h(hash_ctx, adrs, nodes, out);
        }
    }
}
