#include "shrincs.h"

namespace SHRINCS {
    PublicKey::PublicKey() : seed(N), sl_root(N), sf_root(N) {}

    SecretKey::SecretKey(): seed(N), prf(N), structure(2), pk() {}

    void generate_random_bytes(unsigned char* buffer, size_t length) {
        std::random_device rd;
        for (size_t i = 0; i < length; ++i) {
            buffer[i] = static_cast<unsigned char>(rd() & 0xFF); 
        }
    }

    bool shrincs_keygen(const std::vector<unsigned char>& seed, const std::vector<unsigned char>& structure, SecretKey& out_sk, std::vector<unsigned char>* out_cache, bool leaves_only)
    {
        if (seed.size() != 3 * N || structure.size() != 2) return false;

        memcpy(out_sk.seed.data(), seed.data(), N);
        memcpy(out_sk.prf.data(), seed.data() + N, N);
        memcpy(out_sk.pk.seed.data(), seed.data() + (N << 1), N);

        CSHA256 hash_ctx;
        sha256_add_to_ctx(hash_ctx, out_sk.pk.seed.data(), N);
        sha256_add_to_ctx(hash_ctx, zeros, 64 - N);

        unsigned char adrs[22] = {0};
        setLayerAddress(adrs, SPHX_LAYER_COUNT - 1);
        XMSS::xmss_node(out_sk.seed.data(), hash_ctx, adrs, 0, SPHX_XMSS_HEIGHT, out_sk.pk.sl_root.data());

        unsigned char* cache = NULL;
        if (out_cache != NULL)
        {
            uint64_t cache_size = FXMSS::fxmss_cache_size(structure.data(), leaves_only);
            if (cache_size == 0) return false;

            out_cache->assign(cache_size, 0);
            cache = out_cache->data();
        }

        if (!FXMSS::fxmss_root(out_sk.seed.data(), hash_ctx, structure.data(), out_sk.pk.sf_root.data(), cache, leaves_only)) return false;
        out_sk.structure = structure;

        return true;
    }

    // A leaf index needs only as many bytes as the tree depth can address.
    static uint32_t leaf_index_size(uint32_t leaf_depth)
    {
        uint32_t bits = leaf_depth < 64 ? leaf_depth : 64;
        return (bits + 7) >> 3;
    }

    bool shrincs_sf_leaf_select(const std::vector<unsigned char>& structure, const uint64_t* state_ctr, uint64_t* out_lr, uint8_t* out_bt)
    {
        if (state_ctr == NULL || structure.size() != 2) return false;

        unsigned char tree_shape = structure[0], tree_depth = structure[1];

        // A depth-zero tree holds no usable leaf.
        if (tree_depth == 0) return false;

        uint64_t ctr = *state_ctr;
        if (tree_shape == FXMSS_SHAPE_UNBALANCED)
        {
            if (ctr == tree_depth)
            {
                *out_lr = 0;
                *out_bt = FXMSS_HEIGHT - tree_depth;
                return true;
            }
            if (ctr < tree_depth)
            {
                *out_lr = 1;
                *out_bt = static_cast<uint8_t>(FXMSS_HEIGHT - 1 - ctr);
                return true;
            }
        }
        else if (tree_shape == FXMSS_SHAPE_BALANCED)
        {
            // At depth 64 and beyond every 64-bit counter names a leaf.
            if (tree_depth >= 64 || ctr < (UINT64_C(1) << tree_depth))
            {
                *out_lr = ctr;
                *out_bt = FXMSS_HEIGHT - tree_depth;
                return true;
            }
        }

        return false;
    }

    bool shrincs_sign(const std::vector<unsigned char>& message, const std::vector<unsigned char>& ctx, const SecretKey& sk, const uint64_t* state_ctr, const std::vector<unsigned char>& opt_rand, std::vector<unsigned char>& out, std::vector<unsigned char>* cache, bool leaves_only)
    {
        if (ctx.size() > 255) return false;

        uint64_t leaf_index;
        uint8_t leaf_height;
        if (!shrincs_sf_leaf_select(sk.structure, state_ctr, &leaf_index, &leaf_height))
        {
            // Bind the stateless signature to the stateful keypair.
            std::vector<unsigned char> bound_message;
            bound_message.reserve(N + message.size());
            bound_message.insert(bound_message.end(), sk.pk.sf_root.begin(), sk.pk.sf_root.end());
            bound_message.insert(bound_message.end(), message.begin(), message.end());

            out.assign(SHRINCS_SL_SIGNATURE_SIZE, 0);
            out[0] = static_cast<unsigned char>(FXMSS_HEIGHT);

            return SLH_DSA::slh_dsa_sign(bound_message.data(), bound_message.size(), ctx.empty() ? NULL : ctx.data(), ctx.size(), sk.seed.data(), sk.prf.data(), sk.pk.seed.data(), sk.pk.sl_root.data(), opt_rand.empty() ? NULL : opt_rand.data(), out.data() + 1);
        }

        std::vector<unsigned char> bound_message;
        bound_message.reserve(2 + ctx.size() + N + message.size());
        bound_message.push_back(0);
        bound_message.push_back(static_cast<unsigned char>(ctx.size()));
        bound_message.insert(bound_message.end(), ctx.begin(), ctx.end());
        bound_message.insert(bound_message.end(), sk.pk.sl_root.begin(), sk.pk.sl_root.end());
        bound_message.insert(bound_message.end(), message.begin(), message.end());

        unsigned char adrs[22] = {0};
        setLayerAddress(adrs, leaf_height);
        setTreeAddress(adrs, leaf_index);

        unsigned char r[N], digest[N << 1];
        prf_msg_sf(sk.prf.data(), sk.pk.seed.data(), adrs, bound_message.data(), bound_message.size(), r);
        h_msg_sf(r, sk.pk.seed.data(), sk.pk.sf_root.data(), adrs, bound_message.data(), bound_message.size(), digest);

        CSHA256 hash_ctx;
        sha256_add_to_ctx(hash_ctx, sk.pk.seed.data(), N);
        sha256_add_to_ctx(hash_ctx, zeros, 64 - N);

        uint32_t leaf_depth = FXMSS_HEIGHT - leaf_height;
        uint32_t index_size = leaf_index_size(leaf_depth);
        out.assign(1 + N + index_size + WOTS_C_COUNTER_SIZE + WOTS_C_CHAINS_SIZE + N * leaf_depth, 0);

        out[0] = leaf_height;
        memcpy(out.data() + 1, r, N);
        for (uint32_t i = 0; i < index_size; i++)
        {
            out[1 + N + i] = static_cast<unsigned char>(leaf_index >> (8 * (index_size - 1 - i)));
        }

        unsigned char* cache_data = NULL;
        if (cache != NULL)
        {
            if (cache->size() != FXMSS::fxmss_cache_size(sk.structure.data(), leaves_only)) return false;
            cache_data = cache->data();
        }

        return FXMSS::fxmss_sign(digest, sk.seed.data(), hash_ctx, leaf_index, leaf_height, sk.structure.data(), cache_data, leaves_only, out.data() + 1 + N + index_size);
    }

    bool shrincs_verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature, const std::vector<unsigned char>& ctx, const PublicKey& pk)
    {
        if (ctx.size() > 255 || signature.empty()) return false;

        // The first byte tells the verifier which path produced the signature.
        unsigned char indicator = signature[0];

        if (indicator == FXMSS_HEIGHT)
        {
            if (signature.size() != SHRINCS_SL_SIGNATURE_SIZE) return false;

            std::vector<unsigned char> bound_message;
            bound_message.reserve(N + message.size());
            bound_message.insert(bound_message.end(), pk.sf_root.begin(), pk.sf_root.end());
            bound_message.insert(bound_message.end(), message.begin(), message.end());

            return SLH_DSA::slh_dsa_verify(bound_message.data(), bound_message.size(), signature.data() + 1, ctx.empty() ? NULL : ctx.data(), ctx.size(), pk.seed.data(), pk.sl_root.data());
        }

        if (signature.size() < SHRINCS_SF_SIGNATURE_SIZE_MIN || signature.size() > SHRINCS_SF_SIGNATURE_SIZE_MAX) return false;

        uint8_t leaf_height = indicator;
        uint32_t leaf_depth = FXMSS_HEIGHT - leaf_height;
        uint32_t index_size = leaf_index_size(leaf_depth);
        if (signature.size() < 1 + N + index_size) return false;

        uint64_t leaf_index = 0;
        for (uint32_t i = 0; i < index_size; i++)
        {
            leaf_index = (leaf_index << 8) | signature[1 + N + i];
        }

        // Reject a leaf index that names no position in a tree of this depth.
        if (leaf_depth < 64 && leaf_index >= (UINT64_C(1) << leaf_depth)) return false;

        uint32_t fxmss_sig_len = signature.size() - 1 - N - index_size;
        if (fxmss_sig_len != WOTS_C_COUNTER_SIZE + WOTS_C_CHAINS_SIZE + N * leaf_depth) return false;

        unsigned char adrs[22] = {0};
        setLayerAddress(adrs, leaf_height);
        setTreeAddress(adrs, leaf_index);

        std::vector<unsigned char> bound_message;
        bound_message.reserve(2 + ctx.size() + N + message.size());
        bound_message.push_back(0);
        bound_message.push_back(static_cast<unsigned char>(ctx.size()));
        bound_message.insert(bound_message.end(), ctx.begin(), ctx.end());
        bound_message.insert(bound_message.end(), pk.sl_root.begin(), pk.sl_root.end());
        bound_message.insert(bound_message.end(), message.begin(), message.end());

        unsigned char digest[N << 1], root[N];
        h_msg_sf(signature.data() + 1, pk.seed.data(), pk.sf_root.data(), adrs, bound_message.data(), bound_message.size(), digest);

        CSHA256 hash_ctx;
        sha256_add_to_ctx(hash_ctx, pk.seed.data(), N);
        sha256_add_to_ctx(hash_ctx, zeros, 64 - N);

        if (!FXMSS::fxmss_pk_from_sig(signature.data() + 1 + N + index_size, fxmss_sig_len, digest, hash_ctx, leaf_index, root))
        {
            return false;
        }

        return memcmp(root, pk.sf_root.data(), N) == 0;
    }
}