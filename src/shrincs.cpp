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

    bool shrincs_keygen(unsigned char* bytes, const std::vector<unsigned char>& structure, SecretKey& out_sk, std::vector<unsigned char>* out_cache)
    {
        if (structure.size() != 2) return false;

        memcpy(out_sk.seed.data(), bytes, N);
        memcpy(out_sk.prf.data(), bytes + N, N);
        memcpy(out_sk.pk.seed.data(), bytes + (N << 1), N);

        CSHA256 hash_ctx;
        sha256_add_to_ctx(hash_ctx, out_sk.pk.seed.data(), N);
        sha256_add_to_ctx(hash_ctx, zeros, 64 - N);

        unsigned char adrs[22] = {0};
        setLayerAddress(adrs, SPHX_LAYER_COUNT - 1);
        XMSS::xmss_node(out_sk.seed.data(), hash_ctx, adrs, 0, SPHX_XMSS_HEIGHT, out_sk.pk.sl_root.data());

        unsigned char* cache = NULL;
        if (out_cache != NULL)
        {
            uint64_t cache_size = FXMSS::fxmss_cache_size(structure.data());
            if (cache_size == 0) return false;

            out_cache->assign(cache_size, 0);
            cache = out_cache->data();
        }

        if (!FXMSS::fxmss_root(out_sk.seed.data(), hash_ctx, structure.data(), out_sk.pk.sf_root.data(), cache)) return false;
        out_sk.structure = structure;

        return true;
    }

    bool shrincs_sf_leaf_select(const std::vector<unsigned char>& structure, uint32_t state_ctr, uint64_t* out_lr, uint8_t* out_bt)
    {
        if (structure.size() != 2) return false;

        unsigned char tree_shape = structure[0], tree_depth = structure[1];
        if (tree_shape == FXMSS_SHAPE_UNBALANCED)
        {
            if (state_ctr == tree_depth && tree_depth > 0)
            {
                *out_lr = 0;
                *out_bt = FXMSS_HEIGHT - tree_depth;
                return true;
            }
            if (state_ctr < tree_depth + 1u)
            {
                *out_lr = 1;
                *out_bt = FXMSS_HEIGHT - 1 - state_ctr;
                return true;
            }
        }
        else if (tree_shape == FXMSS_SHAPE_BALANCED)
        {
            if (tree_depth > 0 && (tree_depth >= 32 || state_ctr < (UINT32_C(1) << tree_depth)))
            {
                *out_lr = state_ctr;
                *out_bt = FXMSS_HEIGHT - tree_depth;
                return true;
            }
        }

        return false;
    }

    bool shrincs_sign(const std::vector<unsigned char>& message, const SecretKey& sk, uint32_t state_ctr, const std::vector<unsigned char>& opt_rand, std::vector<unsigned char>& out, std::vector<unsigned char>* cache)
    {
        uint64_t leaf_index;
        uint8_t leaf_height;
        if (!shrincs_sf_leaf_select(sk.structure, state_ctr, &leaf_index, &leaf_height))
        {
            std::vector<unsigned char> bound_message;
            bound_message.reserve(N + message.size());
            bound_message.insert(bound_message.end(), sk.pk.sf_root.begin(), sk.pk.sf_root.end());
            bound_message.insert(bound_message.end(), message.begin(), message.end());

            out.assign(SPHX_SIGNATURE_SIZE, 0);

            return SLH_DSA::slh_dsa_sign(bound_message.data(), bound_message.size(), NULL, 0, sk.seed.data(), sk.prf.data(), sk.pk.seed.data(), sk.pk.sl_root.data(), opt_rand.empty() ? NULL : opt_rand.data(), out.data());
        }

        std::vector<unsigned char> bound_message;
        bound_message.reserve(N + message.size());
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
        out.assign(N + 8 + 2 + WOTS_C_CHAINS_SIZE + N * leaf_depth, 0);

        memcpy(out.data(), r, N);

        uint64_t leaf_index_be = htobe64(leaf_index);
        memcpy(out.data() + N, &leaf_index_be, 8);

        unsigned char* cache_data = NULL;
        if (cache != NULL)
        {
            if (cache->size() != FXMSS::fxmss_cache_size(sk.structure.data())) return false;
            cache_data = cache->data();
        }

        return FXMSS::fxmss_sign(digest, sk.seed.data(), hash_ctx, leaf_index, leaf_height, sk.structure.data(), cache_data, out.data() + N + 8);
    }

    bool shrincs_verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature, const PublicKey& pk)
    {
        if (signature.size() == SPHX_SIGNATURE_SIZE)
        {
            std::vector<unsigned char> bound_message;
            bound_message.reserve(N + message.size());
            bound_message.insert(bound_message.end(), pk.sf_root.begin(), pk.sf_root.end());
            bound_message.insert(bound_message.end(), message.begin(), message.end());

            return SLH_DSA::slh_dsa_verify(bound_message.data(), bound_message.size(), signature.data(), NULL, 0, pk.seed.data(), pk.sl_root.data());
        }

        if (signature.size() < N + 8) return false;

        uint32_t fxmss_sig_len = signature.size() - N - 8;
        if (fxmss_sig_len < FXMSS_SIGNATURE_SIZE_MIN || fxmss_sig_len > FXMSS_SIGNATURE_SIZE_MAX) return false;

        if ((fxmss_sig_len - 2) % N != 0) return false;

        uint32_t leaf_depth = ((fxmss_sig_len - 2) >> 4) - WOTS_C_CHAIN_COUNT;
        uint32_t leaf_height = FXMSS_HEIGHT - leaf_depth;

        uint64_t leaf_index_be;
        memcpy(&leaf_index_be, signature.data() + N, 8);
        uint64_t leaf_index = be64toh(leaf_index_be);

        if (leaf_depth < 64 && leaf_index >= (UINT64_C(1) << leaf_depth)) return false;

        unsigned char adrs[22] = {0};
        setLayerAddress(adrs, leaf_height);
        setTreeAddress(adrs, leaf_index);

        std::vector<unsigned char> bound_message;
        bound_message.reserve(N + message.size());
        bound_message.insert(bound_message.end(), pk.sl_root.begin(), pk.sl_root.end());
        bound_message.insert(bound_message.end(), message.begin(), message.end());

        unsigned char digest[N << 1], root[N];
        h_msg_sf(signature.data(), pk.seed.data(), pk.sf_root.data(), adrs, bound_message.data(), bound_message.size(), digest);

        CSHA256 hash_ctx;
        sha256_add_to_ctx(hash_ctx, pk.seed.data(), N);
        sha256_add_to_ctx(hash_ctx, zeros, 64 - N);

        if (!FXMSS::fxmss_pk_from_sig(signature.data() + N + 8, fxmss_sig_len, digest, hash_ctx, leaf_index, root))
        {
            return false;
        }

        return memcmp(root, pk.sf_root.data(), N) == 0;
    }
}