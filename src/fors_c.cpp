#include "fors_c.h"

namespace FORS_C {
    uint32_t extract_bits(const unsigned char* message, uint32_t start_bit_idx, uint32_t bits_amount)
    {
        uint32_t byte_idx = start_bit_idx / 8;
        uint32_t bit_in_byte_idx = start_bit_idx % 8;

        uint32_t res = 0;
        unsigned char* byte = new unsigned char;
        for (uint32_t i = 0; i < bits_amount;)
        {
            memcpy(byte, message + byte_idx, 1);

            if (bits_amount - i < 8)
            {
                uint32_t bits_read = bits_amount - i;

                res <<= bits_read;
                res += *byte >> (8 - bits_read);
                break;
            }
            else
            {
                uint32_t bits_read = 8 - bit_in_byte_idx;

                res <<= bits_read;
                res += ((unsigned char)(*byte << bit_in_byte_idx)) >> bit_in_byte_idx;
                i += bits_read;
            }

            byte_idx++;
            bit_in_byte_idx = 0;
        }

        delete byte;
        return res;
    }

    void fors_msg_to_indices(const unsigned char* message, uint32_t* out_buffer)
    {
        for (uint32_t i = 0; i < K; i++)
        {
            out_buffer[i] = extract_bits(message, i * A, A);
        }
    }

    uint32_t fors_grind(const unsigned char* message, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, unsigned char* adrs, uint32_t* out, unsigned char* digest_out, unsigned char* r_out)
    {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        // Or random(n)
        unsigned char opt_rand[N];
        memcpy(opt_rand, pk_seed, N);

        unsigned char res[32];
        uint32_t tmp_indices[K];

        setTypeAndClear(adrs, FORS_GRIND);

        for (uint32_t ctr = 0; ctr < UINT32_MAX; ctr++)
        {
            prf_msg(sk_prf, pk_seed, opt_rand, message, 32, true, ctr, R_LEN, r_out);

            auto ctx_ = sha256_add_to_ctx(ctx, adrs, 32);
            ctx_ = sha256_add_to_ctx(ctx_, r_out, R_LEN);
            ctx_ = sha256_add_to_ctx(ctx_, pk_seed, N);
            ctx_ = sha256_add_to_ctx(ctx_, pk_root, N);
            ctx_ = sha256_add_to_ctx(ctx_, message, 32);

            sha256_finalize_32(ctx_, res);
            fors_msg_to_indices(res, tmp_indices);
            if (tmp_indices[K - 1] == 0) 
            {
                memcpy(digest_out, res, 32);
                memcpy(out, tmp_indices, K * sizeof(uint32_t));
                return ctr;
            }
        }

        throw std::runtime_error("Unnable to find valid fors message digest");
    }

    unsigned char* fors_sk_gen(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t tree_idx, uint32_t leaf_idx)
    {
        setTypeAndClear(adrs, FORS_PRF);
        setKeyPairAddress(adrs, tree_idx);
        setTreeIndex(adrs, leaf_idx);

        unsigned char* res = new unsigned char[N];
        auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, sk_seed, N);
        sha256_finalize(ctx, res);

        return res;
    }

    unsigned char* fors_treehash(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t tree_idx, uint32_t target_height, uint32_t start_idx)
    {
        unsigned char* res = new unsigned char[N];

        if (target_height == 0)
        {
            auto sk = fors_sk_gen(sk_seed, hash_ctx, adrs, tree_idx, start_idx);
            setTypeAndClear(adrs, FORS_HASH);
            setKeyPairAddress(adrs, tree_idx);
            setTreeHeight(adrs, 0);
            setTreeIndex(adrs, start_idx);

            auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, sk, N);
            sha256_finalize(ctx, res);

            delete[] sk;
            return res;
        }
        auto left = fors_treehash(sk_seed, hash_ctx, adrs, tree_idx, target_height - 1, start_idx);
        auto right = fors_treehash(sk_seed, hash_ctx, adrs, tree_idx, target_height - 1, start_idx + pow(2, target_height - 1));

        setTypeAndClear(adrs, FORS_TREE);
        setKeyPairAddress(adrs, tree_idx);
        setTreeHeight(adrs, target_height);
        setTreeIndex(adrs, start_idx >> target_height);

        auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, left, N);
        ctx = sha256_add_to_ctx(ctx, right, N);
        sha256_finalize(ctx, res);

        delete[] left;
        delete[] right;

        return res;
    }

    unsigned char* fors_auth_path(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t tree_idx, uint32_t leaf_idx)
    {
        unsigned char* auth = new unsigned char[A * N];
        unsigned char* tmp;
        for (uint32_t i = 0; i < A; i++)
        {
            uint32_t sibling_start = (leaf_idx ^ (1 << i)) & (0xFFFFFFF << i);
            tmp = fors_treehash(sk_seed, hash_ctx, adrs, tree_idx, i, sibling_start);
            memcpy(auth + N*i, tmp, N);
            delete[] tmp;
        }

        return auth;
    }

    unsigned char* fors_sign(const unsigned char* message, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, unsigned char* digest_out)
    {
        unsigned char* sig = new unsigned char[FORS_SIGN_LEN];

        unsigned char* r = new unsigned char[R_LEN];

        uint32_t indices[K];
        uint32_t ctr = fors_grind(message, sk_prf, pk_seed, pk_root, adrs, indices, digest_out, r);

        memcpy(sig, r, R_LEN);
        uint32_t offset = R_LEN;

        // uint32_t ctr_be = htonl(ctr);
        // memcpy(sig + offset, reinterpret_cast<const unsigned char*>(&ctr_be), 4);
        // offset += 4;

        for (uint32_t i = 0; i < K - 1; i++)
        {
            auto sk_i = fors_sk_gen(sk_seed, hash_ctx, adrs, i, indices[i]);
            auto auth_i = fors_auth_path(sk_seed, hash_ctx, adrs, i, indices[i]);

            memcpy(sig + offset, sk_i, N);
            offset += N;

            memcpy(sig + offset, auth_i, A * N);
            offset += A * N;

            delete[] sk_i;
            delete[] auth_i;
        }

        delete[] r;
        
        return sig;
    }

    unsigned char* fors_pk_from_sig(const unsigned char* sig, const unsigned char* message, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs)
    {
        unsigned char r[R_LEN];
        memcpy(r, sig, R_LEN);
        uint32_t offset = R_LEN;

        // uint32_t ctr;
        // memcpy(&ctr, sig + offset, 4);
        // offset += 4;

        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        setTypeAndClear(adrs, FORS_GRIND);
        ctx = sha256_add_to_ctx(ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, r, R_LEN);
        // ctx = sha256_add_to_ctx(ctx, reinterpret_cast<const unsigned char*>(&ctr), 4);
        ctx = sha256_add_to_ctx(ctx, pk_seed, N);
        ctx = sha256_add_to_ctx(ctx, pk_root, N);
        ctx = sha256_add_to_ctx(ctx, message, 32);

        unsigned char digest[32];
        sha256_finalize_32(ctx, digest);

        uint32_t indices[K];
        fors_msg_to_indices(digest, indices);
        
        if (indices[K - 1] != 0)
        {
            throw std::runtime_error("Fors message digest is not valid");
        }

        unsigned char roots[K-1][N];

        unsigned char node[N];
        unsigned char sk_i[N];
        unsigned char auth_i[A * N];
        unsigned char auth_part[N];
        for (uint32_t i = 0; i < K - 1; i++)
        {
            memcpy(sk_i, sig + offset, N);
            memcpy(auth_i, sig + offset + N, A * N);
            offset += (A + 1) * N;

            setTypeAndClear(adrs, FORS_HASH);
            setKeyPairAddress(adrs, i);
            setTreeHeight(adrs, 0);
            setTreeIndex(adrs, indices[i]);

            auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, sk_i, N);
            sha256_finalize(ctx, node);
            uint32_t idx = indices[i];

            for (uint32_t h = 0; h < A; h++)
            {
                setTypeAndClear(adrs, FORS_TREE);
                setKeyPairAddress(adrs, i);
                setTreeHeight(adrs, h + 1);
                setTreeIndex(adrs, idx >> 1);

                memcpy(auth_part, auth_i + N * h, N);

                ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
                if ((idx & 1) == 0)
                {
                    ctx = sha256_add_to_ctx(ctx, node, N);
                    ctx = sha256_add_to_ctx(ctx, auth_part, N);
                }
                else
                {
                    ctx = sha256_add_to_ctx(ctx, auth_part, N);
                    ctx = sha256_add_to_ctx(ctx, node, N);
                }

                sha256_finalize(ctx, node);
                idx >>= 1;
            }

            memcpy(roots[i], node, N);
        }

        setTypeAndClear(adrs, FORS_PK);

        ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);

        for(auto i : roots) 
        {
            ctx = sha256_add_to_ctx(ctx, i, N);
        }

        unsigned char* res = new unsigned char[N];
        sha256_finalize(ctx, res);

        return res;
    }
}