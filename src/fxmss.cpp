#include "fxmss.h"
#include "fxmss_bds.h"

namespace FXMSS
{
    static const uint64_t CACHE_SLOT_ABSENT = UINT64_MAX;

    static uint64_t shift_right(uint64_t value, uint32_t bits)
    {
        return bits >= 64 ? 0 : value >> bits;
    }

    static uint64_t uxmss_cache_slot(unsigned char tree_depth, uint64_t node_index, uint32_t node_depth)
    {
        if (node_index > 1 || node_depth < 1 || node_depth > tree_depth) return CACHE_SLOT_ABSENT;

        return 2 * (uint64_t)(node_depth - 1) + node_index;
    }

    static bool uxmss_cache_build(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, const unsigned char* structure, uint64_t node_index, uint32_t node_height, unsigned char* cache, unsigned char* out)
    {
        uint32_t node_depth = FXMSS_HEIGHT - node_height;
        unsigned char tree_depth = structure[1];

        if (node_index == 1 || node_depth == tree_depth)
        {
            setLayerAddress(adrs, node_height);
            setTreeAddress(adrs, node_index);
            wots_c_pk_gen(sk_seed, hash_ctx, adrs, out);
        }
        else
        {
            if (node_index != 0) return false;

            unsigned char left_right[N << 1];
            if (!uxmss_cache_build(sk_seed, hash_ctx, adrs, structure, 0, node_height - 1, cache, left_right)) return false;
            if (!uxmss_cache_build(sk_seed, hash_ctx, adrs, structure, 1, node_height - 1, cache, left_right + N)) return false;

            setLayerAddress(adrs, node_height);
            setTreeAddress(adrs, node_index);
            setType(adrs, SF_FXMSS_TREE);
            set_10_14(adrs, 0);
            set_14_22(adrs, 0);

            h(hash_ctx, adrs, left_right, out);
        }

        uint64_t slot = uxmss_cache_slot(tree_depth, node_index, node_depth);
        if (slot != CACHE_SLOT_ABSENT) memcpy(cache + slot * N, out, N);

        return true;
    }

    uint64_t fxmss_cache_size(const unsigned char* structure)
    {
        unsigned char tree_shape = structure[0], tree_depth = structure[1];

        if (tree_depth == 0) return 0;
        if (tree_shape == FXMSS_SHAPE_UNBALANCED) return 2 * (uint64_t)tree_depth * N;
        if (tree_shape == FXMSS_SHAPE_BALANCED) return BDS::state_size(tree_depth);

        return 0;
    }

    bool fxmss_root(const unsigned char* sk_seed, CSHA256& hash_ctx, const unsigned char* structure, unsigned char* out_root, unsigned char* out_cache)
    {
        unsigned char adrs[22] = {0};

        if (out_cache == NULL)
        {
            return fxmss_node(sk_seed, hash_ctx, adrs, structure, 0, FXMSS_HEIGHT, out_root);
        }

        unsigned char tree_shape = structure[0], tree_depth = structure[1];
        if (fxmss_cache_size(structure) == 0) return false;

        if (tree_shape == FXMSS_SHAPE_UNBALANCED)
        {
            return uxmss_cache_build(sk_seed, hash_ctx, adrs, structure, 0, FXMSS_HEIGHT, out_cache, out_root);
        }

        return BDS::init(sk_seed, hash_ctx, tree_depth, out_cache, out_root);
    }

    bool fxmss_node(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, const unsigned char* structure, uint64_t node_index, uint32_t node_height, unsigned char* out)
    {
        uint32_t node_depth = FXMSS_HEIGHT - node_height;
        unsigned char tree_shape = structure[0], tree_depth = structure[1];

        bool is_uxmss_leaf = tree_shape == FXMSS_SHAPE_UNBALANCED && (node_index == 1 || node_depth == tree_depth);
        bool is_bxmss_leaf = tree_shape == FXMSS_SHAPE_BALANCED && (node_depth == tree_depth);

        if (is_uxmss_leaf || is_bxmss_leaf)
        {
            setLayerAddress(adrs, node_height);
            setTreeAddress(adrs, node_index);
            wots_c_pk_gen(sk_seed, hash_ctx, adrs, out);
            return true;
        }

        if (
            (tree_shape == FXMSS_SHAPE_UNBALANCED && node_index != 0) || 
            (tree_shape == FXMSS_SHAPE_BALANCED && node_depth >= tree_depth)
        )
        {
            return false;
        }

        uint64_t lchild_index = node_index << 1;
        uint32_t child_height = node_height - 1;
        unsigned char left_right[N << 1];
        if (!(
            fxmss_node(sk_seed, hash_ctx, adrs, structure, lchild_index, child_height, left_right) &&
            fxmss_node(sk_seed, hash_ctx, adrs, structure, lchild_index + 1, child_height, left_right + N)))
        {
            return false;
        }

        setLayerAddress(adrs, node_height);
        setTreeAddress(adrs, node_index);
        setType(adrs, SF_FXMSS_TREE);
        set_10_14(adrs, 0);
        set_14_22(adrs, 0);

        h(hash_ctx, adrs, left_right, out);
        return true;
    }

    bool fxmss_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, uint64_t leaf_index, uint32_t leaf_height, const unsigned char* structure, unsigned char* cache, unsigned char* out)
    {
        uint32_t leaf_depth = FXMSS_HEIGHT - leaf_height;
        unsigned char tree_shape = structure[0], tree_depth = structure[1];

        if (
            (tree_shape == FXMSS_SHAPE_UNBALANCED && leaf_index != 1 && leaf_depth != tree_depth) ||
            (tree_shape == FXMSS_SHAPE_BALANCED && leaf_depth != tree_depth)
        )
        {
            return false;
        }

        unsigned char adrs[22] = {0};
        setLayerAddress(adrs, leaf_height);
        setTreeAddress(adrs, leaf_index);
        if (!wots_c_sign(message, sk_seed, hash_ctx, adrs, out)) return false;

        unsigned char* auth = out + WOTS_C_CHAINS_SIZE + 2;

        if (cache != NULL && tree_shape == FXMSS_SHAPE_BALANCED)
        {
            if (!BDS::auth_path(cache, tree_depth, leaf_index, auth)) return false;

            return BDS::advance(sk_seed, hash_ctx, tree_depth, cache);
        }

        uint64_t sibling_index;
        uint32_t sibling_height, offset = 0;
        for (uint32_t i = 0; i < leaf_depth; i++)
        {
            sibling_index = shift_right(leaf_index, i) ^ 1;
            sibling_height = leaf_height + i;

            if (cache != NULL)
            {
                uint64_t slot = uxmss_cache_slot(tree_depth, sibling_index, FXMSS_HEIGHT - sibling_height);
                if (slot == CACHE_SLOT_ABSENT) return false;

                memcpy(auth + offset, cache + slot * N, N);
            }
            else if (!fxmss_node(sk_seed, hash_ctx, adrs, structure, sibling_index, sibling_height, auth + offset))
            {
                return false;
            }

            offset += N;
        }

        return true;
    }

    bool fxmss_pk_from_sig(const unsigned char* sig, uint32_t sig_len, const unsigned char* message, CSHA256& hash_ctx, uint64_t leaf_index, unsigned char* out)
    {
        uint32_t leaf_depth = (sig_len - 2 - WOTS_C_CHAINS_SIZE) >> 4;
        if (leaf_depth < 64 && leaf_index >= (UINT64_C(1) << leaf_depth))
        {
            return false;
        }

        uint32_t leaf_height = FXMSS_HEIGHT - leaf_depth;

        unsigned char adrs[22] = {0};
        setLayerAddress(adrs, leaf_height);
        setTreeAddress(adrs, leaf_index);
        if (!wots_c_pk_from_sig(sig, message, hash_ctx, adrs, out)) return false;

        setType(adrs, SF_FXMSS_TREE);
        set_10_14(adrs, 0);
        set_14_22(adrs, 0);

        uint32_t offset = WOTS_C_CHAINS_SIZE + 2;
        unsigned char nodes[N << 1];
        for (uint32_t i = 0; i < leaf_depth; i++)
        {
            adrs[0] += 1;
            setTreeAddress(adrs, shift_right(leaf_index, i + 1));

            if((shift_right(leaf_index, i) & 1) == 1)
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

        return true;
    }
}