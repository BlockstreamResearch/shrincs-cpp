#include "wots_c.h"

namespace WOTS_C 
{
    void base_w(const unsigned char* message, unsigned char* out_buffer) 
    {
        int w_log = log2(W);
        int w_mod = W - 1;

        int in_idx = 0;
        int bits = 0;
        int total = 0;

        for (uint32_t i = 0; i < L; i++)
        {
            if (bits == 0) 
            {
                total = message[in_idx];
                in_idx++;
                bits = 8;
            }
            bits -= w_log;
            out_buffer[i] = (total >> bits) & (w_mod);
        }
    }

    void chain(const unsigned char* m, uint32_t start, uint32_t steps, SHA256_CTX hash_ctx, unsigned char* adrs, unsigned char* out) 
    {
        memcpy(out, m, N);

        for (uint32_t i = start; i < start + steps; i++)
        {
            setHashAddress(adrs, i);
            auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, out, N);
            sha256_finalize(ctx, out);
        }
    }

    unsigned char* wots_pk_gen(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t keypair, bool sf)
    {
        uint32_t WOTS_HASH, WOTS_PK, WOTS_PRF_TYPE;
        if (sf)
        {
            WOTS_HASH = SF_WOTS_HASH;
            WOTS_PK = SF_WOTS_PK;
            WOTS_PRF_TYPE = SF_WOTS_PRF;
        }
        else
        {
            WOTS_HASH = SL_WOTS_HASH;
            WOTS_PK = SL_WOTS_PK;
            WOTS_PRF_TYPE = SL_WOTS_PRF;
        }

        unsigned char pk[L][N];
        uint32_t steps = W - 1;

        for (uint32_t i = 0; i < L; i++)
        {
            setTypeAndClear(adrs, WOTS_PRF_TYPE);
            setKeyPairAddress(adrs, keypair);
            setChainAddress(adrs, i);
            
            auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, sk_seed, N);

            unsigned char sk_i[N];
            sha256_finalize(ctx, sk_i);

            setTypeAndClear(adrs, WOTS_HASH);
            setKeyPairAddress(adrs, keypair);
            setChainAddress(adrs, i);

            chain(sk_i, 0, steps, hash_ctx, adrs, pk[i]);
        }
        
        setTypeAndClear(adrs, WOTS_PK);
        setKeyPairAddress(adrs, keypair);

        auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);

        for(auto i : pk) 
        {
            ctx = sha256_add_to_ctx(ctx, i, N);
        }

        unsigned char* res = new unsigned char[N];
        sha256_finalize(ctx, res);

        return res;
    }

    uint32_t wots_grind(const unsigned char* message, uint32_t message_len, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t keypair, unsigned char* msg_out, bool sf)
    {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        if (sf)
        {
            setTypeAndClear(adrs, SF_WOTS_GRIND);
        }
        else
        {
            setTypeAndClear(adrs, SL_WOTS_GRIND);
        }

        setKeyPairAddress(adrs, keypair);
        
        ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, message, message_len);

        std::atomic<uint64_t> current_ctr{0};
        std::atomic<bool> found{false};
        std::atomic<uint32_t> result_ctr{0};

        unsigned int num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 4;

        auto worker = [&]() {
            unsigned char res[N];
            unsigned char tmp_msg[L];

            while (!found.load(std::memory_order_relaxed)) {
                uint64_t ctr = current_ctr.fetch_add(1, std::memory_order_relaxed);
                
                if (ctr > UINT32_MAX) {
                    break;
                }

                uint32_t ctr_be = htonl(ctr);
                auto ctx_ = sha256_add_to_ctx(ctx, reinterpret_cast<const unsigned char*>(&ctr_be), 4);

                sha256_finalize(ctx_, res);

                base_w(res, tmp_msg);

                uint32_t sum = 0;
                for (uint32_t i = 0; i < L; i++) sum += tmp_msg[i];

                if (sum == SWN) {
                    bool expected = false;
                    if (found.compare_exchange_strong(expected, true)) {
                        result_ctr.store(static_cast<uint32_t>(ctr));
                        memcpy(msg_out, tmp_msg, L);
                    }
                    break;
                }
            }
        };

        std::vector<std::thread> threads;
        for (unsigned int i = 0; i < num_threads; ++i) {
            threads.emplace_back(worker);
        }

        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }

        if (found.load()) {
            return result_ctr.load();
        }
        
        throw std::runtime_error("Unnable to find valid wots message digest");
    }

    bool wots_digest(const unsigned char* message, uint32_t message_len, SHA256_CTX hash_ctx, uint32_t ctr, unsigned char* adrs, uint32_t keypair, unsigned char* msg_out, bool sf)
    {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        if (sf)
        {
            setTypeAndClear(adrs, SF_WOTS_GRIND);
        }
        else
        {
            setTypeAndClear(adrs, SL_WOTS_GRIND);
        }

        setKeyPairAddress(adrs, keypair);

        ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
        ctx = sha256_add_to_ctx(ctx, message, message_len);

        uint32_t ctr_be = htonl(ctr);
        ctx = sha256_add_to_ctx(ctx, reinterpret_cast<const unsigned char*>(&ctr_be), 4);

        unsigned char res[N];
        sha256_finalize(ctx, res);

        base_w(res, msg_out);

        uint32_t sum = 0;
        for (uint32_t i = 0; i < L; i++) sum += msg_out[i];

        return sum == SWN;
    }

    unsigned char* wots_sign(const unsigned char* message, uint32_t message_len, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t keypair, bool sf, bool is_internal) 
    {
        unsigned char* sig = new unsigned char[WOTS_SIGN_LEN];

        uint32_t WOTS_HASH, WOTS_PRF_TYPE, H_MSG_TYPE;
        if (sf)
        {
            WOTS_HASH = SF_WOTS_HASH;
            WOTS_PRF_TYPE = SF_WOTS_PRF;
            H_MSG_TYPE = SF_H_MSG;
        }
        else
        {
            WOTS_HASH = SL_WOTS_HASH;
            WOTS_PRF_TYPE = SL_WOTS_PRF;
            H_MSG_TYPE = SL_H_MSG;
        }

        // Or random(n)
        unsigned char opt_rand[N];
        memcpy(opt_rand, pk_seed, N);
        unsigned char* r = new unsigned char[R_LEN];
        prf_msg(sk_prf, pk_seed, opt_rand, message, message_len, false, 0, R_LEN, r);

        unsigned char* digest = new unsigned char[N];
        if (is_internal)
        {
            memcpy(digest, message, message_len);
        }
        else
        {
            SHA256_CTX ctx;
            SHA256_Init(&ctx);

            setTypeAndClear(adrs, H_MSG_TYPE);
            ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, r, R_LEN);
            ctx = sha256_add_to_ctx(ctx, pk_root, N);
            ctx = sha256_add_to_ctx(ctx, message, message_len);
            sha256_finalize(ctx, digest);
        }

        unsigned char msg[L];
        uint32_t ctr = wots_grind(digest, N, hash_ctx, adrs, keypair, msg, sf);

        memcpy(sig, r, R_LEN);
        uint32_t offset = R_LEN;

        uint32_t ctr_be = htonl(ctr);
        memcpy(sig + offset, reinterpret_cast<const unsigned char*>(&ctr_be), 4);
        offset += 4;

        for (uint32_t i = 0; i < L; i++)
        {
            setTypeAndClear(adrs, WOTS_PRF_TYPE);
            setKeyPairAddress(adrs, keypair);
            setChainAddress(adrs, i);

            auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, sk_seed, N);

            unsigned char sk_i[N];
            sha256_finalize(ctx, sk_i);

            setTypeAndClear(adrs, WOTS_HASH);
            setKeyPairAddress(adrs, keypair);
            setChainAddress(adrs, i);

            unsigned char tmp[N];
            chain(sk_i, 0, msg[i], hash_ctx, adrs, tmp);
            memcpy(sig + offset, tmp, N);
            offset += N;
        }
        
        delete[] r;
        delete[] digest;
        return sig;
    }

    unsigned char* wots_pk_from_sig(const unsigned char* sig, const unsigned char* message, uint32_t message_len, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t keypair, bool sf, bool is_internal)
    {
        uint32_t WOTS_HASH, WOTS_PK, H_MSG_TYPE;
        if (sf)
        {
            WOTS_HASH = SF_WOTS_HASH;
            WOTS_PK = SF_WOTS_PK;
            H_MSG_TYPE = SF_H_MSG;
        }
        else
        {
            WOTS_HASH = SL_WOTS_HASH;
            WOTS_PK = SL_WOTS_PK;
            H_MSG_TYPE = SL_H_MSG;
        }

        unsigned char r[R_LEN];
        memcpy(r, sig, R_LEN);
        uint32_t offset = R_LEN;

        uint32_t ctr;
        memcpy(&ctr, sig + offset, 4);
        ctr = ntohl(ctr);
        offset += 4;

        unsigned char* digest = new unsigned char[N];
        if (is_internal)
        {
            memcpy(digest, message, message_len);
        }
        else
        {
            SHA256_CTX ctx;
            SHA256_Init(&ctx);

            setTypeAndClear(adrs, H_MSG_TYPE);
            ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
            ctx = sha256_add_to_ctx(ctx, r, R_LEN);
            ctx = sha256_add_to_ctx(ctx, pk_root, N);
            ctx = sha256_add_to_ctx(ctx, message, message_len);
            sha256_finalize(ctx, digest);
        }

        unsigned char msg[L];
        bool valid = wots_digest(digest, N, hash_ctx, ctr, adrs, keypair, msg, sf);

        if (!valid)
        {
            delete[] digest;
            throw std::runtime_error("Wots message digest is not valid");
        }

        uint32_t to_step = W - 1;
        unsigned char pk[L][N];
        unsigned char sig_i[N];
        for (uint32_t i = 0; i < L; i++)
        {
            setTypeAndClear(adrs, WOTS_HASH);
            setKeyPairAddress(adrs, keypair);
            setChainAddress(adrs, i);

            memcpy(sig_i, sig + offset, N);
            offset += N;
            
            chain(sig_i, msg[i], to_step - msg[i], hash_ctx, adrs, pk[i]);
        }

        setTypeAndClear(adrs, WOTS_PK);
        setKeyPairAddress(adrs, keypair);
        
        auto ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);

        for(auto i : pk) 
        {
            ctx = sha256_add_to_ctx(ctx, i, N);
        }

        unsigned char* res = new unsigned char[N];
        sha256_finalize(ctx, res);

        delete[] digest;
        return res;
    }
}