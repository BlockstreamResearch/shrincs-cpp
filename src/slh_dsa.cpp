#include "slh_dsa.h"

namespace SLH_DSA
{
    void slh_dsa_digest_message(const unsigned char* r, const unsigned char* pk_seed, const unsigned char* sl_root, const unsigned char* message, uint32_t m_len, unsigned char* out_digest, uint64_t* out_tree, uint32_t* out_leaf)
    {
        unsigned char digest[32];
        h_msg_sl(r, pk_seed, sl_root, message, m_len, digest);

        memcpy(out_digest, digest, FORS_DIGEST_SIZE);

        uint32_t tree_index_size = (SPHX_TREE_INDEX_BITS + 7) >> 3;
        uint32_t leaf_index_size = (SPHX_XMSS_HEIGHT + 7) >> 3;

        unsigned char* tree_index_digest = digest + FORS_DIGEST_SIZE;
        unsigned char* leaf_index_digest = tree_index_digest + tree_index_size;

        uint64_t tree_index = 0, leaf_index = 0;

        memcpy(reinterpret_cast<unsigned char*>(&tree_index) + 8 - tree_index_size, tree_index_digest, tree_index_size);
        *out_tree = be64toh(tree_index) & ((UINT64_C(1) << SPHX_TREE_INDEX_BITS) - 1);

        memcpy(reinterpret_cast<unsigned char*>(&leaf_index) + 8 - leaf_index_size, leaf_index_digest, leaf_index_size);
        *out_leaf = be64toh(leaf_index) & ((UINT32_C(1) << SPHX_XMSS_HEIGHT) - 1);
    }

    void slh_dsa_sign_internal(const unsigned char* message, uint32_t m_len, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* sl_root, const unsigned char* opt_rand, unsigned char* out)
    {
        unsigned char opt_rand_[N];
        if (opt_rand == NULL)
            memcpy(opt_rand_, pk_seed, N);
        else
            memcpy(opt_rand_, opt_rand, N);

        unsigned char r[N], fors_digest[FORS_DIGEST_SIZE];
        prf_msg_sl(sk_prf, opt_rand_, message, m_len, r);

        uint64_t tree_index;
        uint32_t leaf_index;
        slh_dsa_digest_message(r, pk_seed, sl_root, message, m_len, fors_digest, &tree_index, &leaf_index);

        memcpy(out, r, N);

        unsigned char adrs[22] = {0};
        setTreeAddress(adrs, tree_index);
        set_10_14(adrs, leaf_index);

        CSHA256 hash_ctx;
        sha256_add_to_ctx(hash_ctx, pk_seed, N);
        sha256_add_to_ctx(hash_ctx, zeros, 64 - N);

        unsigned char fors_pk[N];
        fors_sign(sk_seed, fors_digest, hash_ctx, adrs, out + N);
        fors_pk_from_sig(out + N, fors_digest, hash_ctx, adrs, fors_pk);
        hypertree_sign(fors_pk, sk_seed, hash_ctx, tree_index, leaf_index, out + N + FORS_SIGNATURE_SIZE);
    }

    bool slh_dsa_verify_internal(const unsigned char* message, uint32_t m_len, const unsigned char* signature, const unsigned char* pk_seed, const unsigned char* sl_root)
    {
        const unsigned char* r = signature, *fors_signature = signature + N, *hypertree_signature = signature + N + FORS_SIGNATURE_SIZE;

        unsigned char fors_digest[FORS_DIGEST_SIZE];
        uint64_t tree_index;
        uint32_t leaf_index;
        slh_dsa_digest_message(r, pk_seed, sl_root, message, m_len, fors_digest, &tree_index, &leaf_index);

        unsigned char adrs[22] = {0};
        setTreeAddress(adrs, tree_index);
        set_10_14(adrs, leaf_index);

        CSHA256 hash_ctx;
        sha256_add_to_ctx(hash_ctx, pk_seed, N);
        sha256_add_to_ctx(hash_ctx, zeros, 64 - N);

        unsigned char fors_pk[N];
        fors_pk_from_sig(fors_signature, fors_digest, hash_ctx, adrs, fors_pk);
        return hypertree_verify(hypertree_signature, fors_pk, hash_ctx, tree_index, leaf_index, sl_root);
    }

    bool slh_dsa_sign(const unsigned char* message, uint32_t m_len, const unsigned char* ctx, uint32_t ctx_len, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* sl_root, const unsigned char* opt_rand, unsigned char* out)
    {
        if (ctx_len > 255) return false;

        unsigned char* contextualized_msg = new unsigned char[2 + ctx_len + m_len];
        contextualized_msg[0] = 0;
        contextualized_msg[1] = ctx_len;
        if (ctx_len) memcpy(contextualized_msg + 2, ctx, ctx_len);
        memcpy(contextualized_msg + 2 + ctx_len, message, m_len);
        slh_dsa_sign_internal(contextualized_msg, 2 + ctx_len + m_len, sk_seed, sk_prf, pk_seed, sl_root, opt_rand, out);

        delete[] contextualized_msg;

        return true;
    }

    bool slh_dsa_verify(const unsigned char* message, uint32_t m_len, const unsigned char* signature, const unsigned char* ctx, uint32_t ctx_len, const unsigned char* pk_seed, const unsigned char* sl_root)
    {
        if (ctx_len > 255) return false;

        unsigned char* contextualized_msg = new unsigned char[2 + ctx_len + m_len];
        contextualized_msg[0] = 0;
        contextualized_msg[1] = ctx_len;
        if (ctx_len) memcpy(contextualized_msg + 2, ctx, ctx_len);
        memcpy(contextualized_msg + 2 + ctx_len, message, m_len);

        bool res = slh_dsa_verify_internal(contextualized_msg, 2 + ctx_len + m_len, signature, pk_seed, sl_root);

        delete[] contextualized_msg;

        return res;
    }
}