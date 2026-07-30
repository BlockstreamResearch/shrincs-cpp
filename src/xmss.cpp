#include "xmss.h"

namespace XMSS 
{
    void xmss_node(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t node_idx, uint32_t node_height, unsigned char* out)
    {
        if (!node_height) 
        {
            set_10_14(adrs, node_idx);
            wots_tw_pk_gen(sk_seed, hash_ctx, adrs, out);
            return;
        }

        uint32_t lchild_index = node_idx << 1;
        uint32_t child_height = node_height - 1;
        unsigned char left_right[N << 1];
        xmss_node(sk_seed, hash_ctx, adrs, lchild_index, child_height, left_right);
        xmss_node(sk_seed, hash_ctx, adrs, lchild_index + 1, child_height, left_right + N);

        setType(adrs, SL_XMSS_TREE);
        set_10_14(adrs, 0);
        set_14_18(adrs, node_height);
        set_18_22(adrs, node_idx);

        h(hash_ctx, adrs, left_right, out);
    }

    void xmss_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t keypair_index, unsigned char* out) 
    {
        set_10_14(adrs, keypair_index);
        wots_tw_sign(message, sk_seed, hash_ctx, adrs, out);
        uint32_t offset = WOTS_TW_CHAINS_SIZE;

        uint32_t sibling_index;
        for (uint32_t i = 0; i < SPHX_XMSS_HEIGHT; i++)
        {
            sibling_index = (keypair_index >> i) ^ 1;
            xmss_node(sk_seed, hash_ctx, adrs, sibling_index, i, out + offset);
            offset += N;
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