#include "pors_fp.h"

namespace PORS_FP {
    uint32_t extract_bits(const unsigned char* message, uint32_t start_bit_idx, uint32_t bits_amount)
    {
        uint32_t res = 0;
        for (uint32_t i = 0; i < bits_amount; i++)
        {
            uint32_t bit_idx = start_bit_idx + i;
            uint32_t byte_idx = bit_idx / 8;
            uint32_t bit_in_byte = bit_idx % 8;
            
            uint32_t bit = (message[byte_idx] >> (7 - bit_in_byte)) & 1;
            res = (res << 1) | bit;
        }
        return res;
    }

    bool uint32_arr_have(uint32_t* arr, uint32_t arr_size, uint32_t elem)
    {
        for (uint32_t i = 0; i < arr_size; i++)
        {
            if (arr[i] == elem)
            {
                return true;
            }
        }
        
        return false;
    }

    unsigned char* pors_msg_to_indices(const unsigned char* message, unsigned char* adrs, SHA256_CTX hash_ctx, uint32_t* indices_out)
    {
        uint32_t b = ceil(log2(T));
        uint32_t c = floor(256.0 / b);

        uint32_t xof_block_idx = ((((1 << b) * K + T - 1) / T) + c - 1) / c;

        unsigned char block[32];
        unsigned char* xof_out = new unsigned char[xof_block_idx * 32];
        uint32_t xof_offset = 0;

        uint32_t indices_amount = 0;

        setTypeAndClear(adrs, PORS_XOF);
        auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, message, 32);

        for (uint32_t blk = 0; blk < UINT32_MAX; blk++)
        {
            uint32_t ctr_be = htonl(blk);
            ctx = sha256_add_to_ctx(ctx, reinterpret_cast<const unsigned char*>(&ctr_be), 4);
            sha256_finalize_32(ctx, block);

            if (blk < xof_block_idx)
            {
                memcpy(xof_out + xof_offset, block, 32);
                xof_offset += 32;
            }

            for (uint32_t i = 0; i < c; i++)
            {
                if (indices_amount == K) break;
                uint32_t candidate = extract_bits(block, i * b, b);
                if (candidate < T && !uint32_arr_have(indices_out, indices_amount, candidate))
                {
                    indices_out[indices_amount] = candidate;
                    indices_amount++;
                }
            }

            if (blk >= xof_block_idx && indices_amount == K)
            {
                std::sort(indices_out, indices_out + K);
                return xof_out;
            }
        }

        throw std::runtime_error("Unable to find valid indices for PORS+FP");
    }

    bool pors_octopus(uint32_t* indices, std::tuple<uint32_t, uint32_t>* A_out, uint32_t& A_len_out)
    {
        uint32_t h = ceil(log2(T));
        uint32_t s = T - (1 << (h - 1));

        std::vector<std::tuple<uint32_t, uint32_t>> I;
        std::vector<std::tuple<uint32_t, uint32_t>> P;

        A_len_out = 0;

        for (uint32_t j = 0; j < K; j++)
        {
            uint32_t i = indices[j];

            if (i < 2 * s)
            {
                I.emplace_back(0, i);
            }
            else
            {
                P.emplace_back(1, i - s);
            }
        }

        for (uint32_t current_lvl = 0; current_lvl < h; current_lvl++)
        {
            std::vector<std::tuple<uint32_t, uint32_t>> P_next;

            uint32_t i = 0;
            while (i < I.size())
            {
                auto [lvl, idx] = I[i];
                auto sib = idx ^ 1;

                if (i + 1 < I.size() && std::get<1>(I[i + 1]) == sib)
                {
                    i += 2;
                }
                else
                {
                    if (A_len_out == M_MAX) {
                        return false;
                    }
                    A_out[A_len_out] = std::make_tuple(current_lvl, sib);
                    A_len_out++;
                    i++;
                }

                P_next.emplace_back(current_lvl + 1, idx >> 1);
            }
            I = P_next;
            I.insert(I.end(), P.begin(), P.end());
            P.clear();

            if (I.size() == 1 && std::get<1>(I[0]) == 0)
            {
                break;
            }
        }

        return true;
    }

    void pors_grind(const unsigned char* message, uint32_t message_len, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, unsigned char* adrs, unsigned char* opt_rand, SHA256_CTX hash_ctx, uint32_t* indices_out, unsigned char* digest_out, unsigned char* r_out)
    {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        setTypeAndClear(adrs, SL_H_MSG);

        ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);

        unsigned char* xof_out;
        auto A = new std::tuple<uint32_t, uint32_t>[M_MAX];
        uint32_t a_len = 0;

        for (uint32_t ctr = 0; ctr < UINT32_MAX; ctr++)
        {
            prf_msg(sk_prf, pk_seed, opt_rand, message, message_len, true, ctr, R_LEN, r_out);

            auto ctx_ = sha256_add_to_ctx(ctx, r_out, R_LEN);
            ctx_ = sha256_add_to_ctx(ctx_, pk_root, N);
            ctx_ = sha256_add_to_ctx(ctx_, message, message_len);
            sha256_finalize_32(ctx_, digest_out);

            xof_out = pors_msg_to_indices(digest_out, adrs, hash_ctx, indices_out);
            if (pors_octopus(indices_out, A, a_len))
            {
                delete[] A;
                delete[] xof_out;

                return;
            }
        }

        delete[] A;
        delete[] xof_out;
        throw std::runtime_error("Unnable to find valid pors message digest");
    }

    unsigned char* pors_sk_gen(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t leaf_idx)
    {
        setTypeAndClear(adrs, PORS_PRF);
        setKeyPairAddress(adrs, 0);
        setTreeIndex(adrs, leaf_idx);

        unsigned char* res = new unsigned char[N];
        auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, sk_seed, N);
        sha256_finalize(ctx, res);

        return res;
    }

    unsigned char* pors_treehash(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t target_height, uint32_t idx)
    {
        unsigned char* res = new unsigned char[N];

        uint32_t h = ceil(log2(T));
        uint32_t s = T - (1 << (h - 1));

        if (target_height == 0)
        {
            auto sk = pors_sk_gen(sk_seed, hash_ctx, adrs, idx);
            setTypeAndClear(adrs, PORS_HASH);
            setKeyPairAddress(adrs, 0);
            setTreeHeight(adrs, 0);
            setTreeIndex(adrs, idx);

            auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, sk, N);
            sha256_finalize(ctx, res);

            delete[] sk;
            return res;
        }
        else if (target_height == 1 && idx >= s)
        {
            uint32_t leaf_idx = s + idx;
            auto sk = pors_sk_gen(sk_seed, hash_ctx, adrs, leaf_idx);
            setTypeAndClear(adrs, PORS_HASH);
            setKeyPairAddress(adrs, 0);
            setTreeHeight(adrs, 0);
            setTreeIndex(adrs, leaf_idx);

            auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, sk, N);
            sha256_finalize(ctx, res);

            delete[] sk;
            return res;
        }

        auto left = pors_treehash(sk_seed, hash_ctx, adrs, target_height - 1, 2 * idx);
        auto right = pors_treehash(sk_seed, hash_ctx, adrs, target_height - 1, 2 * idx + 1);

        setTypeAndClear(adrs, PORS_TREE);
        setKeyPairAddress(adrs, 0);
        setTreeHeight(adrs, target_height);
        setTreeIndex(adrs, idx);

        auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, left, N);
        ctx = sha256_add_to_ctx(ctx, right, N);
        sha256_finalize(ctx, res);

        delete[] left;
        delete[] right;

        return res;
    }

    unsigned char* pors_auth_path(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t* indices, uint32_t& A_len)
    {
        unsigned char* tmp;
        auto A = new std::tuple<uint32_t, uint32_t>[M_MAX];
        A_len = 0;

        pors_octopus(indices, A, A_len);
        unsigned char* auth = new unsigned char[A_len * N];

        for (uint32_t i = 0; i < A_len; i++)
        {
            auto [lvl, idx] = A[i];
            tmp = pors_treehash(sk_seed, hash_ctx, adrs, lvl, idx);
            memcpy(auth + N*i, tmp, N);
            delete[] tmp;
        }

        delete[] A;
        return auth;
    }

    unsigned char* pors_sign(const unsigned char* message, uint32_t message_len, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, unsigned char* digest_out)
    {
        unsigned char* sig = new unsigned char[PORS_SIGN_LEN]();

        unsigned char* r = new unsigned char[R_LEN];

        // Or random(n)
        unsigned char opt_rand[N];
        memcpy(opt_rand, pk_seed, N);

        uint32_t indices[K];
        pors_grind(message, message_len, sk_prf, pk_seed, pk_root, adrs, opt_rand, hash_ctx, indices, digest_out, r);

        memcpy(sig, r, R_LEN);
        uint32_t offset = R_LEN;

        for (uint32_t i = 0; i < K; i++)
        {
            auto sk_i = pors_sk_gen(sk_seed, hash_ctx, adrs, indices[i]);
            memcpy(sig + offset, sk_i, N);
            offset += N;
            
            delete[] sk_i;
        }

        uint32_t A_len;
        auto auth_i = pors_auth_path(sk_seed, hash_ctx, adrs, indices, A_len);
        memcpy(sig + offset, auth_i, A_len * N);

        delete[] auth_i;
        delete[] r;
        
        return sig;
    }

    unsigned char* pors_pk_from_sig(const unsigned char* sig, uint32_t indices[K], SHA256_CTX hash_ctx, unsigned char* adrs)
    {
        uint32_t offset = R_LEN;

        uint32_t h = ceil(log2(T));
        uint32_t s = T - (1 << (h - 1));

        unsigned char sk_i[N];

        std::vector<std::tuple<uint32_t, uint32_t, std::vector<unsigned char>>> I;
        std::vector<std::tuple<uint32_t, uint32_t, std::vector<unsigned char>>> P;

        unsigned char val[N];

        auto A = new std::tuple<uint32_t, uint32_t>[M_MAX];
        uint32_t A_len = 0;
        pors_octopus(indices, A, A_len);
        delete[] A;

        for (uint32_t i = 0; i < K; i++)
        {
            memcpy(sk_i, sig + offset, N);
            offset += N;

            setTypeAndClear(adrs, PORS_HASH);
            setKeyPairAddress(adrs, 0);
            setTreeHeight(adrs, 0);
            setTreeIndex(adrs, indices[i]);

            auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, sk_i, N);
            sha256_finalize(ctx, val);

            if (indices[i] < 2*s)
            {
                I.emplace_back(0, indices[i], std::vector(val, val + N));
            }
            else 
            {
                P.emplace_back(1, indices[i] - s, std::vector(val, val + N));
            }
        }

        unsigned char parent_val[N];
        unsigned char auth_val[N];

        for (uint32_t cur_lvl = 0; cur_lvl < h; cur_lvl++)
        {
            auto paired = std::vector<bool>(I.size(), false);
            for (uint32_t i = 0; i < I.size(); i++)
            {
                if (i + 1 < I.size() && std::get<1>(I[i + 1]) == (std::get<1>(I[i]) ^ 1))
                {
                    paired[i] = true;
                    paired[i + 1] = true;
                }
            }
            
            auto P_next = std::vector<std::tuple<uint32_t, uint32_t, std::vector<unsigned char>>>();
            for (uint32_t i = 0; i < I.size(); i++)
            {
                auto [lvl, idx, val] = I[i];
                if (paired[i] && (idx & 1) == 0)
                {
                    continue;
                }

                setTypeAndClear(adrs, PORS_TREE);
                setKeyPairAddress(adrs, 0);
                setTreeHeight(adrs, cur_lvl + 1);
                setTreeIndex(adrs, idx >> 1);

                auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);

                if (paired[i])
                {
                    ctx = sha256_add_to_ctx(ctx, std::get<2>(I[i-1]).data(), N);
                    ctx = sha256_add_to_ctx(ctx, val.data(), N);
                }
                else
                {
                    memcpy(auth_val, sig + offset, N);
                    offset += N;
                    if ((idx & 1) == 0) 
                    {
                        ctx = sha256_add_to_ctx(ctx, val.data(), N);
                        ctx = sha256_add_to_ctx(ctx, auth_val, N);
                    }
                    else
                    {
                        ctx = sha256_add_to_ctx(ctx, auth_val, N);
                        ctx = sha256_add_to_ctx(ctx, val.data(), N);
                    }
                }
                sha256_finalize(ctx, parent_val);

                P_next.emplace_back(std::make_tuple(cur_lvl + 1, idx >> 1, std::vector(parent_val, parent_val + N)));
            }

            I = P_next;
            I.insert(I.end(), P.begin(), P.end());
            P.clear();

            if (I.size() == 1 && std::get<1>(I[0]) == 0)
            {
                break;
            }
        }

        for (uint32_t i = A_len; i < M_MAX; i++)
        {
            bool is_all_zeros = std::all_of(sig + offset, sig + offset + N, [](unsigned char c) { return c == 0; });
            offset += N;

            if (!is_all_zeros)
            {
                throw std::runtime_error("Incorect zero-padding in PORS+FP");
            }
        }

        auto root = std::get<2>(I[0]);

        auto res = new unsigned char[N];
        setTypeAndClear(adrs, PORS_PK);

        auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, root.data(), N);
        sha256_finalize(ctx, res);
        return res;
    }
}