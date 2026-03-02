#include "shrincs.h"

namespace SHRINCS {
    PublicKey::PublicKey() : seed(N), root(N) {}

    SecretKey::SecretKey(): seed(N), prf(N), sf(N), sl(N), pk() {}

    State::State() {}

    void generate_random_bytes(unsigned char* buffer, size_t length) {
        if (RAND_bytes(buffer, length) != 1) {
            throw std::runtime_error("OpenSSL failed to generate random bytes");
        }
    }

    void parse_idx(const unsigned char* digest, uint32_t* idx_tree, uint32_t* idx_leaf)
    {
        uint32_t ht_offset = K * A;
        uint32_t idx = FORS_C::extract_bits(digest, ht_offset, HSL);

        for (uint32_t layer = 0; layer < D; layer++)
        {
            uint32_t leaf = idx & ((1 << H_PRIME) - 1);
            memcpy(idx_leaf + layer, &leaf, 4);
            idx >>= H_PRIME;

            uint32_t tree = idx & ((1 << (HSL - (layer + 1) * H_PRIME)) - 1);
            memcpy(idx_tree + layer, &tree, 4);
        }
    }

    void shrincs_key_gen(PublicKey& out_pk, SecretKey& out_sk, State& out_state) 
    {
        unsigned char* seed = new unsigned char[3*N];
        generate_random_bytes(seed, 3*N);

        shrincs_restore(seed, out_pk, out_sk, out_state);

        delete[] seed;
        out_state.valid = true;
    }

    void shrincs_restore(const unsigned char* seed, PublicKey& out_pk, SecretKey& out_sk, State& out_state)
    {
        unsigned char* sk_seed = new unsigned char[N];
        unsigned char* sk_prf = new unsigned char[N];
        unsigned char* pk_seed = new unsigned char[N];

        memcpy(sk_seed, seed, N);
        memcpy(sk_prf, seed + N, N);
        memcpy(pk_seed, seed + 2*N, N);

        unsigned char* adrs = new unsigned char[32]();

        SHA256_CTX hash_ctx;
        SHA256_Init(&hash_ctx);

        hash_ctx = sha256_add_to_ctx(hash_ctx, pk_seed, N);
        // Add zeros
        hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 16);

        auto pk_sf = UXMSS::uxmss_root(sk_seed, hash_ctx, adrs);

        setLayerAddress(adrs, D - 1);
        setTreeAddress(adrs, 0, 0);
        auto pk_sl = XMSS::xmss_root(sk_seed, hash_ctx, adrs, H_PRIME);

        setLayerAddress(adrs, 0);
        setTreeAddress(adrs, 0, 0);
        setTypeAndClear(adrs, ROOT);
        unsigned char* pk_root = new unsigned char[N];
        auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, pk_sf, N);
        ctx = sha256_add_to_ctx(ctx, pk_sl, N);
        sha256_finalize(ctx, pk_root);

        memcpy(out_sk.seed.data(), sk_seed, N);
        memcpy(out_sk.prf.data(), sk_prf, N);
        memcpy(out_sk.sf.data(), pk_sf, N);
        memcpy(out_sk.sl.data(), pk_sl, N);
        memcpy(out_sk.pk.seed.data(), pk_seed, N);
        memcpy(out_sk.pk.root.data(), pk_root, N);
        
        memcpy(out_pk.seed.data(), pk_seed, N);
        memcpy(out_pk.root.data(), pk_root, N);

        out_state.q = 0;
        out_state.valid = false;

        delete[] sk_seed;
        delete[] sk_prf;
        delete[] pk_seed;
        delete[] pk_root;
        delete[] adrs;
        delete[] pk_sl;
        delete[] pk_sf;
    }

    unsigned char* shrincs_sign_stateful(const unsigned char* message, SecretKey& sk, State& state)
    {
        if (!state.valid) {
            throw std::runtime_error("Invalid state");
        }

        uint32_t q = state.q + 1;
        if (q > HSF + 1)
        {
            throw std::runtime_error("Invalid signature number");
        }

        unsigned char* adrs = new unsigned char[32]();

        SHA256_CTX hash_ctx;
        SHA256_Init(&hash_ctx);

        hash_ctx = sha256_add_to_ctx(hash_ctx, sk.pk.seed.data(), N);
        // Add zeros
        hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 16);

        auto uxmss_sig = UXMSS::uxmss_sign(message, sk.seed.data(), sk.prf.data(), sk.pk.seed.data(), sk.pk.root.data(), hash_ctx, adrs, q);

        unsigned char* sig = new unsigned char[N + WOTS_SIGN_LEN + q * N];
        memcpy(sig, sk.sl.data(), N);
        memcpy(sig + N, uxmss_sig, WOTS_SIGN_LEN + q * N);
        state.q = q;
        state.valid = true;

        delete[] uxmss_sig;
        delete[] adrs;
        return sig;
    }

    unsigned char* shrincs_sign_stateless(const unsigned char* message, SecretKey& sk)
    {
        unsigned char* adrs = new unsigned char[32]();

        SHA256_CTX hash_ctx;
        SHA256_Init(&hash_ctx);

        hash_ctx = sha256_add_to_ctx(hash_ctx, sk.pk.seed.data(), N);
        // Add zeros
        hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 16);

        unsigned char* digest = new unsigned char[32];

        auto fors_sig = FORS_C::fors_sign(message, sk.seed.data(), sk.prf.data(), sk.pk.seed.data(), sk.pk.root.data(), hash_ctx, adrs, digest);

        uint32_t indices[K];
        FORS_C::fors_msg_to_indices(digest, indices);
        if (indices[K - 1] != 0)
        {
            throw std::runtime_error("Fors message digest is not valid");
        }

        uint32_t* tree_idx = new uint32_t[D];
        uint32_t* leaf_idx = new uint32_t[D];
        parse_idx(digest, tree_idx, leaf_idx);

        setLayerAddress(adrs, 0);
        setTreeAddress(adrs, 0, tree_idx[0] * pow(2, H_PRIME) + leaf_idx[0]);
        auto fors_pk = FORS_C::fors_pk_from_sig(fors_sig, indices, hash_ctx, adrs);

        unsigned char* ht_sig = new unsigned char[XMSS_SIGN_LEN * D];
        auto msg = fors_pk;

        for (uint32_t layer = 0; layer < D; layer++)
        {
            setLayerAddress(adrs, layer);
            setTreeAddress(adrs, 0, tree_idx[layer]);
            auto xmss_sig = XMSS::xmss_sign(msg, sk.seed.data(), sk.prf.data(), sk.pk.seed.data(), sk.pk.root.data(), hash_ctx, adrs, H_PRIME, leaf_idx[layer]);
            memcpy(ht_sig + XMSS_SIGN_LEN * layer, xmss_sig, XMSS_SIGN_LEN);

            delete[] msg;
            if (layer < D - 1)
            {
                msg = XMSS::xmss_root(sk.seed.data(), hash_ctx, adrs, H_PRIME);
            }

            delete[] xmss_sig;
        }
        
        unsigned char* sig = new unsigned char[SL_SIZE];
        memcpy(sig, sk.sf.data(), N);
        memcpy(sig + N, fors_sig, FORS_SIGN_LEN);
        memcpy(sig + N + FORS_SIGN_LEN, ht_sig, XMSS_SIGN_LEN * D);

        delete[] digest;
        delete[] tree_idx;
        delete[] leaf_idx;
        delete[] fors_sig;
        delete[] ht_sig;
        delete[] adrs;

        return sig;
    }

    bool shrincs_verify_stateful(const unsigned char* message, const unsigned char* sig, uint32_t sig_len, PublicKey& pk)
    {
        unsigned char* adrs = new unsigned char[32]();
        unsigned char* sl = new unsigned char[N];
        memcpy(sl, sig, N);

        const unsigned char* uxmss_sig = sig + N;

        uint32_t auth_len = sig_len - N - WOTS_SIGN_LEN;
        uint32_t q = auth_len / N;
        if (q < 1 || q > HSF + 1)
        {
            return false;
        }

        SHA256_CTX hash_ctx;
        SHA256_Init(&hash_ctx);

        hash_ctx = sha256_add_to_ctx(hash_ctx, pk.seed.data(), N);
        // Add zeros
        hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 16);

        try
        {
            auto sf = UXMSS::uxmss_pk_from_sig(uxmss_sig, uxmss_sig + WOTS_SIGN_LEN, message, pk.seed.data(), pk.root.data(), hash_ctx, adrs, q);

            unsigned char* root = new unsigned char[N];
            setTypeAndClear(adrs, ROOT);
            auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, sf, N);
            ctx = sha256_add_to_ctx(ctx, sl, N);
            sha256_finalize(ctx, root);

            bool is_valid = memcmp(root, pk.root.data(), N) == 0;

            delete[] sf;
            delete[] adrs;
            delete[] sl;
            delete[] root;

            return is_valid;
        }
        catch(const std::exception& e)
        {
            return false;
        }
    }

    bool shrincs_verify_stateless(const unsigned char* message, const unsigned char* sig, PublicKey& pk)
    {
        unsigned char* adrs = new unsigned char[32]();
        unsigned char* sf = new unsigned char[N];

        memcpy(sf, sig, N);
        uint32_t offset = N;

        const unsigned char* fors_sig = sig + offset;
        offset += FORS_SIGN_LEN;

        const unsigned char* r = fors_sig;

        // uint32_t ctr;
        // memcpy(&ctr, fors_sig + R_LEN, 4);
        // ctr = ntohl(ctr);

        SHA256_CTX hash_ctx;
        SHA256_Init(&hash_ctx);

        hash_ctx = sha256_add_to_ctx(hash_ctx, pk.seed.data(), N);
        // Add zeros
        hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 16);

        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        setTypeAndClear(adrs, H_MSG);
        ctx = sha256_add_to_ctx(ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, r, R_LEN);
        ctx = sha256_add_to_ctx(ctx, pk.seed.data(), N);
        ctx = sha256_add_to_ctx(ctx, pk.root.data(), N);
        ctx = sha256_add_to_ctx(ctx, message, 32);

        unsigned char* digest = new unsigned char[32];
        sha256_finalize_32(ctx, digest);

        uint32_t indices[K];
        FORS_C::fors_msg_to_indices(digest, indices);
        if (indices[K - 1] != 0)
        {
            throw std::runtime_error("Fors message digest is not valid");
        }

        uint32_t* tree_idx = new uint32_t[D];
        uint32_t* leaf_idx = new uint32_t[D];
        parse_idx(digest, tree_idx, leaf_idx);

        setLayerAddress(adrs, 0);
        setTreeAddress(adrs, 0, tree_idx[0] * pow(2, H_PRIME) + leaf_idx[0]);

        unsigned char* fors_pk;
        try{
            fors_pk = FORS_C::fors_pk_from_sig(fors_sig, indices, hash_ctx, adrs);
        }
        catch(const std::exception& e)
        {
            return false;
        }

        auto msg = fors_pk;

        for (uint32_t layer = 0; layer < D; layer++)
        {
            auto xmss_sig = sig + offset;
            offset += XMSS_SIGN_LEN;
            auto wots_sig = xmss_sig;
            auto auth = xmss_sig + WOTS_SIGN_LEN;
            setLayerAddress(adrs, layer);
            setTreeAddress(adrs, 0, tree_idx[layer]);
            try {
                unsigned char* new_msg = XMSS::xmss_pk_from_sig(wots_sig, auth, msg, pk.seed.data(), pk.root.data(), hash_ctx, adrs, H_PRIME, leaf_idx[layer]);
                delete[] msg;
                msg = new_msg;
            }
            catch(const std::exception& e)
            {
                return false;
            }
        }
        
        auto sl = msg;

        setLayerAddress(adrs, 0);
        setTreeAddress(adrs, 0, 0);
        unsigned char* root = new unsigned char[N];
        setTypeAndClear(adrs, ROOT);
        ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, sf, N);
        ctx = sha256_add_to_ctx(ctx, sl, N);
        sha256_finalize(ctx, root);

        bool is_valid = memcmp(root, pk.root.data(), N) == 0;

        delete[] adrs;
        delete[] sf;
        delete[] digest;
        delete[] sl;
        delete[] tree_idx;
        delete[] leaf_idx;
        delete[] root;

        return is_valid;
    }

    bool shrincs_verify(const unsigned char* message, const unsigned char* sig, uint32_t sig_len, PublicKey& pk)
    {
        if (sig_len <= MAX_SF_SIZE)
        {
            return shrincs_verify_stateful(message, sig, sig_len, pk);
        }
        else
        {
            return shrincs_verify_stateless(message, sig, pk);
        }
    }
}