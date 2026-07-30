#include "fors.h"

namespace FORS
{
    void fors_sk_gen(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t node_index, unsigned char* out)
    {
        setType(adrs, SL_FORS_PRF);
        set_14_18(adrs, 0);
        set_18_22(adrs, node_index);
        prf(hash_ctx, sk_seed, adrs, out);
    }

    void fors_node(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t node_index, uint32_t node_height, unsigned char* out)
    {
        if (!node_height)
        {
            fors_sk_gen(sk_seed, hash_ctx, adrs, node_index, out);
            setType(adrs, SL_FORS_TREE);
            set_14_18(adrs, 0);
            set_18_22(adrs, node_index);
            f(hash_ctx, adrs, out, out);
            return;
        }

        uint32_t lchild_index = node_index << 1;
        uint32_t child_height = node_height - 1;
        unsigned char left_right[N << 1];
        fors_node(sk_seed, hash_ctx, adrs, lchild_index, child_height, left_right);
        fors_node(sk_seed, hash_ctx, adrs, lchild_index + 1, child_height, left_right + N);

        setType(adrs, SL_FORS_TREE);
        set_14_18(adrs, node_height);
        set_18_22(adrs, node_index);
        h(hash_ctx, adrs, left_right, out);
    }

    void fors_sign(const unsigned char* sk_seed, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out)
    {
        uint32_t indexes[SPHX_FORS_COUNT];
        WOTS::base_2b(message, SPHX_FORS_HEIGHT, SPHX_FORS_COUNT, indexes);

        uint32_t leaf_index, sibling_index, offset = 0;
        for (uint32_t i = 0; i < SPHX_FORS_COUNT; i++)
        {
            leaf_index = i * (1 << SPHX_FORS_HEIGHT) + indexes[i];
            fors_sk_gen(sk_seed, hash_ctx, adrs, leaf_index, out + offset);
            offset += N;

            for (uint32_t j = 0; j < SPHX_FORS_HEIGHT; j++)
            {
                sibling_index = i * (1 << (SPHX_FORS_HEIGHT - j)) + ((indexes[i] >> j) ^ 1);
                fors_node(sk_seed, hash_ctx, adrs, sibling_index, j, out + offset);
                offset += N;
            }
        }
    }

    void fors_pk_from_sig(const unsigned char* sig, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out)
    {
        uint32_t indexes[SPHX_FORS_COUNT];
        WOTS::base_2b(message, SPHX_FORS_HEIGHT, SPHX_FORS_COUNT, indexes);

        uint32_t offset = 0, tree_index, offset_roots = 0;
        unsigned char nodes[N << 1], roots[SPHX_FORS_COUNT << 4]; 
        for (uint32_t i = 0; i < SPHX_FORS_COUNT; i++)
        {
            tree_index = i * (1 << (SPHX_FORS_HEIGHT)) + indexes[i];
            setType(adrs, SL_FORS_TREE);
            set_14_18(adrs, 0);
            set_18_22(adrs, tree_index);
            f(hash_ctx, adrs, sig + offset, out);
            offset += N;

            for (uint32_t j = 0; j < SPHX_FORS_HEIGHT; j++)
            {
                set_14_18(adrs, j + 1);
                set_18_22(adrs, tree_index >> (j + 1));

                if(((indexes[i] >> j) & 1) == 1)
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

            memcpy(roots + offset_roots, out, N);
            offset_roots += N;
        }

        setType(adrs, SL_FORS_ROOTS);
        set_14_22(adrs, 0);
        t_k(hash_ctx, adrs, roots, out);
    }
}