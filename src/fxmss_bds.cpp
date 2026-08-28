#include "fxmss_bds.h"

namespace BDS
{
    static const uint32_t TH_NEXT_IDX = 0;
    static const uint32_t TH_STACKUSAGE = 4;
    static const uint32_t TH_COMPLETED = 8;
    static const uint32_t TH_NODE = 9;
    static const uint32_t TH_ENTRY = TH_NODE + N;

    static const uint32_t OFF_NEXT_LEAF = 0;
    static const uint32_t OFF_STACKOFFSET = 4;
    static const uint32_t OFF_STACKLEVELS = 8;

    static const unsigned char DEPTH_MAX = 31;
    static const uint32_t LEAF_BLOCK = 512;

    struct Layout
    {
        uint32_t depth, k;
        uint64_t stack, auth, keep, retain, treehash, total;
    };

    static bool layout(unsigned char tree_depth, Layout& out)
    {
        if (tree_depth < 2 || tree_depth > DEPTH_MAX) return false;

        out.depth = tree_depth;
        out.k = (tree_depth & 1) ? 3 : 2;

        uint64_t retain_count = (UINT64_C(1) << out.k) - out.k - 1;

        out.stack = OFF_STACKLEVELS + (uint64_t)tree_depth + 1;
        out.auth = out.stack + ((uint64_t)tree_depth + 1) * N;
        out.keep = out.auth + (uint64_t)tree_depth * N;
        out.retain = out.keep + ((uint64_t)tree_depth >> 1) * N;
        out.treehash = out.retain + retain_count * N;
        out.total = out.treehash + (uint64_t)(tree_depth - out.k) * TH_ENTRY;

        return true;
    }

    uint64_t state_size(unsigned char tree_depth)
    {
        Layout l;
        return layout(tree_depth, l) ? l.total : 0;
    }

    static uint32_t get_u32(const unsigned char* p)
    {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
    }

    static void put_u32(unsigned char* p, uint32_t value)
    {
        p[0] = (unsigned char)(value >> 24);
        p[1] = (unsigned char)(value >> 16);
        p[2] = (unsigned char)(value >> 8);
        p[3] = (unsigned char)value;
    }

    static void gen_leaf(const unsigned char* sk_seed, CSHA256& hash_ctx, uint32_t tree_depth, uint64_t index, unsigned char* out)
    {
        const unsigned char structure[2] = {FXMSSShape::FXMSS_SHAPE_BALANCED, (unsigned char)tree_depth};

        unsigned char adrs[22] = {0};
        setLayerAddress(adrs, FXMSS_HEIGHT - tree_depth);
        setTreeAddress(adrs, index);
        memcpy(adrs + 10, structure, 2);
        WOTS::wots_c_pk_gen(sk_seed, hash_ctx, adrs, out);
    }

    static void hash_pair(CSHA256& hash_ctx, uint32_t tree_depth, uint32_t child_level, uint64_t parent_index, const unsigned char* in, unsigned char* out)
    {
        unsigned char adrs[22] = {0};
        setLayerAddress(adrs, FXMSS_HEIGHT - tree_depth + child_level + 1);
        setTreeAddress(adrs, parent_index);
        setType(adrs, SF_FXMSS_TREE);
        set_10_14(adrs, 0);
        set_14_22(adrs, 0);

        h(hash_ctx, adrs, in, out);
    }

    static uint64_t retain_slot(uint32_t tree_depth, uint32_t node_level, uint64_t leaf_index)
    {
        int64_t offset = ((int64_t)1 << (tree_depth - 1 - node_level)) + (int64_t)node_level - (int64_t)tree_depth;
        int64_t row = (int64_t)(((leaf_index >> node_level) - 3) >> 1);

        return (uint64_t)(offset + row);
    }

    static void treehash_init(const unsigned char* sk_seed, CSHA256& hash_ctx, const Layout& l, unsigned char* state, unsigned char* out_root)
    {
        unsigned char* levels = state + OFF_STACKLEVELS;
        unsigned char* stack = state + l.stack;
        unsigned char* auth = state + l.auth;
        unsigned char* retain = state + l.retain;

        for (uint32_t i = 0; i < l.depth - l.k; i++)
        {
            unsigned char* th = state + l.treehash + i * TH_ENTRY;
            put_u32(th + TH_NEXT_IDX, 0);
            put_u32(th + TH_STACKUSAGE, 0);
            th[TH_COMPLETED] = 1;
        }

        uint32_t stackoffset = 0;
        uint64_t leaf_count = UINT64_C(1) << l.depth;

        unsigned char block[LEAF_BLOCK * N];

        for (uint64_t start = 0; start < leaf_count; start += LEAF_BLOCK)
        {
            uint64_t remaining = leaf_count - start;
            int block_count = (int)(remaining < LEAF_BLOCK ? remaining : LEAF_BLOCK);

            #pragma omp parallel for schedule(static) if(block_count >= 16)
            for (int i = 0; i < block_count; i++)
            {
                gen_leaf(sk_seed, hash_ctx, l.depth, start + (uint64_t)i, block + (size_t)i * N);
            }

            for (int b = 0; b < block_count; b++)
            {
                uint64_t idx = start + (uint64_t)b;

                memcpy(stack + (uint64_t)stackoffset * N, block + (size_t)b * N, N);
                levels[stackoffset] = 0;
                stackoffset++;

                while (stackoffset > 1 && levels[stackoffset - 1] == levels[stackoffset - 2])
                {
                    uint32_t node_level = levels[stackoffset - 1];
                    const unsigned char* top = stack + (uint64_t)(stackoffset - 1) * N;

                    if ((idx >> node_level) == 1)
                    {
                        memcpy(auth + (uint64_t)node_level * N, top, N);
                    }
                    else if (node_level < l.depth - l.k)
                    {
                        if ((idx >> node_level) == 3) memcpy(state + l.treehash + node_level * TH_ENTRY + TH_NODE, top, N);
                    }
                    else
                    {
                        memcpy(retain + retain_slot(l.depth, node_level, idx) * N, top, N);
                    }

                    hash_pair(hash_ctx, l.depth, node_level, idx >> (node_level + 1),
                              stack + (uint64_t)(stackoffset - 2) * N, stack + (uint64_t)(stackoffset - 2) * N);
                    levels[stackoffset - 2]++;
                    stackoffset--;
                }
            }
        }

        memcpy(out_root, stack, N);
    }

    static void treehash_update(const unsigned char* sk_seed, CSHA256& hash_ctx, const Layout& l, unsigned char* state, uint32_t inst)
    {
        unsigned char* th = state + l.treehash + inst * TH_ENTRY;
        unsigned char* levels = state + OFF_STACKLEVELS;
        unsigned char* stack = state + l.stack;

        uint32_t stackoffset = get_u32(state + OFF_STACKOFFSET);
        uint32_t stackusage = get_u32(th + TH_STACKUSAGE);
        uint32_t next_idx = get_u32(th + TH_NEXT_IDX);

        unsigned char node[N << 1];
        uint32_t node_level = 0;

        gen_leaf(sk_seed, hash_ctx, l.depth, next_idx, node);

        while (stackusage > 0 && levels[stackoffset - 1] == node_level)
        {
            memcpy(node + N, node, N);
            memcpy(node, stack + (uint64_t)(stackoffset - 1) * N, N);

            hash_pair(hash_ctx, l.depth, node_level, next_idx >> (node_level + 1), node, node);
            node_level++;
            stackusage--;
            stackoffset--;
        }

        if (node_level == inst)
        {
            memcpy(th + TH_NODE, node, N);
            th[TH_COMPLETED] = 1;
        }
        else
        {
            memcpy(stack + (uint64_t)stackoffset * N, node, N);
            levels[stackoffset] = (unsigned char)node_level;
            stackoffset++;
            stackusage++;
            next_idx++;
        }

        put_u32(state + OFF_STACKOFFSET, stackoffset);
        put_u32(th + TH_STACKUSAGE, stackusage);
        put_u32(th + TH_NEXT_IDX, next_idx);
    }

    static uint32_t minheight_on_stack(const Layout& l, const unsigned char* state, uint32_t stackusage)
    {
        uint32_t stackoffset = get_u32(state + OFF_STACKOFFSET);
        const unsigned char* levels = state + OFF_STACKLEVELS;

        uint32_t r = l.depth;
        for (uint32_t i = 0; i < stackusage; i++)
        {
            if (levels[stackoffset - i - 1] < r) r = levels[stackoffset - i - 1];
        }

        return r;
    }

    static void treehash_rounds(const unsigned char* sk_seed, CSHA256& hash_ctx, const Layout& l, unsigned char* state, uint32_t updates)
    {
        for (uint32_t j = 0; j < updates; j++)
        {
            uint32_t lowest = l.depth;
            uint32_t chosen = l.depth - l.k;

            for (uint32_t i = 0; i < l.depth - l.k; i++)
            {
                const unsigned char* th = state + l.treehash + i * TH_ENTRY;
                uint32_t stackusage = get_u32(th + TH_STACKUSAGE);

                uint32_t low;
                if (th[TH_COMPLETED]) low = l.depth;
                else if (stackusage == 0) low = i;
                else low = minheight_on_stack(l, state, stackusage);

                if (low < lowest)
                {
                    chosen = i;
                    lowest = low;
                }
            }

            if (chosen == l.depth - l.k) break;

            treehash_update(sk_seed, hash_ctx, l, state, chosen);
        }
    }

    static void bds_round(const unsigned char* sk_seed, CSHA256& hash_ctx, const Layout& l, unsigned char* state, uint64_t leaf_index)
    {
        unsigned char* auth = state + l.auth;
        unsigned char* keep = state + l.keep;
        unsigned char* retain = state + l.retain;

        uint32_t tau = l.depth;
        for (uint32_t i = 0; i < l.depth; i++)
        {
            if (!((leaf_index >> i) & 1))
            {
                tau = i;
                break;
            }
        }

        unsigned char buf[N << 1];
        if (tau > 0)
        {
            memcpy(buf, auth + (uint64_t)(tau - 1) * N, N);
            memcpy(buf + N, keep + (uint64_t)((tau - 1) >> 1) * N, N);
        }

        if (tau < l.depth - 1 && !((leaf_index >> (tau + 1)) & 1))
        {
            memcpy(keep + (uint64_t)(tau >> 1) * N, auth + (uint64_t)tau * N, N);
        }

        if (tau == 0)
        {
            gen_leaf(sk_seed, hash_ctx, l.depth, leaf_index, auth);
            return;
        }

        hash_pair(hash_ctx, l.depth, tau - 1, leaf_index >> tau, buf, auth + (uint64_t)tau * N);

        for (uint32_t i = 0; i < tau; i++)
        {
            if (i < l.depth - l.k)
            {
                memcpy(auth + (uint64_t)i * N, state + l.treehash + i * TH_ENTRY + TH_NODE, N);
            }
            else
            {
                int64_t offset = ((int64_t)1 << (l.depth - 1 - i)) + (int64_t)i - (int64_t)l.depth;
                int64_t row = (int64_t)(((leaf_index >> i) - 1) >> 1);
                memcpy(auth + (uint64_t)i * N, retain + (uint64_t)(offset + row) * N, N);
            }
        }

        uint32_t limit = tau < l.depth - l.k ? tau : l.depth - l.k;
        for (uint32_t i = 0; i < limit; i++)
        {
            uint64_t start = leaf_index + 1 + 3 * (UINT64_C(1) << i);
            if (start < (UINT64_C(1) << l.depth))
            {
                unsigned char* th = state + l.treehash + i * TH_ENTRY;
                put_u32(th + TH_NEXT_IDX, (uint32_t)start);
                put_u32(th + TH_STACKUSAGE, 0);
                th[TH_COMPLETED] = 0;
            }
        }
    }

    bool init(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char tree_depth, unsigned char* state, unsigned char* out_root)
    {
        Layout l;
        if (!layout(tree_depth, l)) return false;

        memset(state, 0, l.total);
        treehash_init(sk_seed, hash_ctx, l, state, out_root);

        put_u32(state + OFF_NEXT_LEAF, 0);
        put_u32(state + OFF_STACKOFFSET, 0);

        return true;
    }

    bool auth_path(const unsigned char* state, unsigned char tree_depth, uint64_t leaf_index, unsigned char* out)
    {
        Layout l;
        if (!layout(tree_depth, l)) return false;
        if (leaf_index != get_u32(state + OFF_NEXT_LEAF)) return false;

        memcpy(out, state + l.auth, (uint64_t)l.depth * N);

        return true;
    }

    bool advance(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char tree_depth, unsigned char* state)
    {
        Layout l;
        if (!layout(tree_depth, l)) return false;

        uint32_t leaf_index = get_u32(state + OFF_NEXT_LEAF);
        if ((uint64_t)leaf_index + 1 < (UINT64_C(1) << l.depth))
        {
            bds_round(sk_seed, hash_ctx, l, state, leaf_index);
            treehash_rounds(sk_seed, hash_ctx, l, state, (l.depth - l.k) >> 1);
        }

        put_u32(state + OFF_NEXT_LEAF, leaf_index + 1);

        return true;
    }
}
