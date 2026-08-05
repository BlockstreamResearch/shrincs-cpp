#include "fxmss.h"
#include "fxmss_bds.h"

namespace FXMSS
{
    static const uint64_t CACHE_SLOT_ABSENT = UINT64_MAX;
    static const uint32_t LEAF_BLOCK = 512;

    static uint64_t shift_right(uint64_t value, uint32_t bits)
    {
        return bits >= 64 ? 0 : value >> bits;
    }

    static uint64_t uxmss_cache_slot(unsigned char tree_depth, uint64_t node_index, uint32_t node_depth)
    {
        if (node_index > 1 || node_depth < 1 || node_depth > tree_depth) return CACHE_SLOT_ABSENT;

        return 2 * (uint64_t)(node_depth - 1) + node_index;
    }

    static uint64_t uxmss_leaf_slot(unsigned char tree_depth, uint64_t node_index, uint32_t node_depth)
    {
        if (node_index == 1 && node_depth >= 1 && node_depth <= tree_depth) return node_depth - 1;
        if (node_index == 0 && node_depth == tree_depth) return tree_depth;

        return CACHE_SLOT_ABSENT;
    }

    static void fxmss_leaf(const unsigned char* sk_seed, CSHA256& hash_ctx, uint32_t leaf_depth, uint64_t leaf_index, unsigned char* out)
    {
        unsigned char adrs[22] = {0};
        setLayerAddress(adrs, FXMSS_HEIGHT - leaf_depth);
        setTreeAddress(adrs, leaf_index);

        wots_c_pk_gen(sk_seed, hash_ctx, adrs, out);
    }

    static void fxmss_parent(CSHA256& hash_ctx, uint32_t parent_depth, uint64_t parent_index, const unsigned char* children, unsigned char* out)
    {
        unsigned char adrs[22] = {0};
        setLayerAddress(adrs, FXMSS_HEIGHT - parent_depth);
        setTreeAddress(adrs, parent_index);
        setType(adrs, SF_FXMSS_TREE);
        set_10_14(adrs, 0);
        set_14_22(adrs, 0);

        h(hash_ctx, adrs, children, out);
    }

    static bool uxmss_cache_build(const unsigned char* sk_seed, CSHA256& hash_ctx, const unsigned char* structure, unsigned char* cache, bool leaves_only, unsigned char* out_root)
    {
        int tree_depth = structure[1];

        #pragma omp parallel for schedule(static) if(tree_depth >= 8)
        for (int depth = 1; depth <= tree_depth; depth++)
        {
            uint64_t slot = leaves_only ? uxmss_leaf_slot(tree_depth, 1, depth) : uxmss_cache_slot(tree_depth, 1, depth);
            fxmss_leaf(sk_seed, hash_ctx, (uint32_t)depth, 1, cache + slot * N);
        }

        uint64_t deepest = leaves_only ? uxmss_leaf_slot(tree_depth, 0, tree_depth) : uxmss_cache_slot(tree_depth, 0, tree_depth);
        fxmss_leaf(sk_seed, hash_ctx, (uint32_t)tree_depth, 0, cache + deepest * N);

        unsigned char node[N], children[N << 1];
        memcpy(node, cache + deepest * N, N);

        for (int depth = tree_depth - 1; depth >= 0; depth--)
        {
            uint64_t sibling = leaves_only ? uxmss_leaf_slot(tree_depth, 1, depth + 1) : uxmss_cache_slot(tree_depth, 1, depth + 1);

            memcpy(children, node, N);
            memcpy(children + N, cache + sibling * N, N);

            fxmss_parent(hash_ctx, (uint32_t)depth, 0, children, node);

            if (!leaves_only && depth > 0) memcpy(cache + uxmss_cache_slot(tree_depth, 0, depth) * N, node, N);
        }

        memcpy(out_root, node, N);

        return true;
    }

    static void uxmss_internal_from_leaves(CSHA256& hash_ctx, unsigned char tree_depth, uint32_t node_depth, const unsigned char* cache, unsigned char* out)
    {
        unsigned char node[N], children[N << 1];
        memcpy(node, cache + uxmss_leaf_slot(tree_depth, 0, tree_depth) * N, N);

        for (int depth = (int)tree_depth - 1; depth >= (int)node_depth; depth--)
        {
            memcpy(children, node, N);
            memcpy(children + N, cache + uxmss_leaf_slot(tree_depth, 1, depth + 1) * N, N);

            fxmss_parent(hash_ctx, (uint32_t)depth, 0, children, node);
        }

        memcpy(out, node, N);
    }

    static bool uxmss_subtree(const unsigned char* sk_seed, CSHA256& hash_ctx, uint32_t tree_depth, uint32_t root_depth, unsigned char* out)
    {
        int count = (int)(tree_depth - root_depth);
        unsigned char leaves[(FXMSS_HEIGHT + 1) * N];

        #pragma omp parallel for schedule(static) if(count >= 8)
        for (int i = 0; i < count; i++)
        {
            fxmss_leaf(sk_seed, hash_ctx, root_depth + 1 + (uint32_t)i, 1, leaves + (size_t)i * N);
        }

        unsigned char node[N], children[N << 1];
        fxmss_leaf(sk_seed, hash_ctx, tree_depth, 0, node);

        for (int depth = (int)tree_depth - 1; depth >= (int)root_depth; depth--)
        {
            memcpy(children, node, N);
            memcpy(children + N, leaves + (size_t)(depth - (int)root_depth) * N, N);

            fxmss_parent(hash_ctx, (uint32_t)depth, 0, children, node);
        }

        memcpy(out, node, N);

        return true;
    }

    static bool bxmss_subtree(const unsigned char* sk_seed, CSHA256& hash_ctx, uint32_t tree_depth, uint64_t root_index, uint32_t root_depth, unsigned char* out)
    {
        uint32_t levels = tree_depth - root_depth;
        if (levels > 32) return false;

        uint64_t leaf_count = UINT64_C(1) << levels;
        uint64_t base = root_index << levels;

        unsigned char stack[(FXMSS_HEIGHT + 1) * N], stack_levels[FXMSS_HEIGHT + 1];
        unsigned char block[LEAF_BLOCK * N];
        uint32_t stackoffset = 0;

        for (uint64_t start = 0; start < leaf_count; start += LEAF_BLOCK)
        {
            uint64_t remaining = leaf_count - start;
            int block_count = (int)(remaining < LEAF_BLOCK ? remaining : LEAF_BLOCK);

            #pragma omp parallel for schedule(static) if(block_count >= 16)
            for (int i = 0; i < block_count; i++)
            {
                fxmss_leaf(sk_seed, hash_ctx, tree_depth, base + start + (uint64_t)i, block + (size_t)i * N);
            }

            for (int b = 0; b < block_count; b++)
            {
                uint64_t idx = base + start + (uint64_t)b;

                memcpy(stack + (size_t)stackoffset * N, block + (size_t)b * N, N);
                stack_levels[stackoffset] = 0;
                stackoffset++;

                while (stackoffset > 1 && stack_levels[stackoffset - 1] == stack_levels[stackoffset - 2])
                {
                    uint32_t level = stack_levels[stackoffset - 1];

                    fxmss_parent(hash_ctx, tree_depth - level - 1, idx >> (level + 1),
                                 stack + (size_t)(stackoffset - 2) * N, stack + (size_t)(stackoffset - 2) * N);
                    stack_levels[stackoffset - 2]++;
                    stackoffset--;
                }
            }
        }

        memcpy(out, stack, N);

        return true;
    }

    uint64_t fxmss_cache_size(const unsigned char* structure, bool leaves_only)
    {
        unsigned char tree_shape = structure[0], tree_depth = structure[1];

        if (tree_depth == 0) return 0;
        if (tree_shape == FXMSS_SHAPE_UNBALANCED) return (leaves_only ? (uint64_t)tree_depth + 1 : 2 * (uint64_t)tree_depth) * N;
        if (tree_shape == FXMSS_SHAPE_BALANCED) return BDS::state_size(tree_depth);

        return 0;
    }

    bool fxmss_root(const unsigned char* sk_seed, CSHA256& hash_ctx, const unsigned char* structure, unsigned char* out_root, unsigned char* out_cache, bool leaves_only)
    {
        unsigned char adrs[22] = {0};

        if (out_cache == NULL)
        {
            return fxmss_node(sk_seed, hash_ctx, adrs, structure, 0, FXMSS_HEIGHT, out_root);
        }

        unsigned char tree_shape = structure[0], tree_depth = structure[1];
        if (fxmss_cache_size(structure, leaves_only) == 0) return false;

        if (tree_shape == FXMSS_SHAPE_UNBALANCED)
        {
            return uxmss_cache_build(sk_seed, hash_ctx, structure, out_cache, leaves_only, out_root);
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

        if (tree_shape == FXMSS_SHAPE_UNBALANCED)
        {
            return uxmss_subtree(sk_seed, hash_ctx, tree_depth, node_depth, out);
        }

        return bxmss_subtree(sk_seed, hash_ctx, tree_depth, node_index, node_depth, out);
    }

    bool fxmss_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, uint64_t leaf_index, uint32_t leaf_height, const unsigned char* structure, unsigned char* cache, bool leaves_only, unsigned char* out)
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
                uint32_t sibling_depth = FXMSS_HEIGHT - sibling_height;
                uint64_t slot = leaves_only ? uxmss_leaf_slot(tree_depth, sibling_index, sibling_depth)
                                            : uxmss_cache_slot(tree_depth, sibling_index, sibling_depth);

                if (slot != CACHE_SLOT_ABSENT)
                {
                    memcpy(auth + offset, cache + slot * N, N);
                }
                else if (leaves_only && sibling_index == 0)
                {
                    uxmss_internal_from_leaves(hash_ctx, tree_depth, sibling_depth, cache, auth + offset);
                }
                else
                {
                    return false;
                }
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