#include "wots.h"

namespace WOTS
{
    uint32_t sum(const uint32_t* arr, uint32_t arr_len)
    {
        uint32_t res = 0;
        for (uint32_t i = 0; i < arr_len; i++)
        {
            res += arr[i];
        }

        return res;
    }

    void base_2b(const unsigned char* message, uint32_t b, uint32_t outlen, uint32_t* out_buffer) 
    {
        uint32_t j = 0;
        uint32_t acc = 0;
        uint32_t bits_filled = 0;

        for (uint32_t i = 0; i < outlen; i++)
        {
            while (bits_filled < b)
            {
                acc = (acc << 8) + message[j];
                j += 1;
                bits_filled += 8;
            }

            bits_filled -= b;
            out_buffer[i] = acc >> bits_filled;
            acc %= 1 << bits_filled;
        }  
    }

    void chain(const unsigned char* m, uint32_t start, uint32_t steps, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out) 
    {
        memcpy(out, m, N);

        for (uint32_t i = start; i < start + steps; i++)
        {
            set_18_22(adrs, i);
            f(hash_ctx, adrs, out, out);
        }
    }

    void wots_tw_message_to_indexes(const unsigned char* message, uint32_t* out_buffer)
    {
        base_2b(message, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT1, out_buffer);
        uint32_t checksum = WOTS_TW_CHECKSUM_MAX - sum(out_buffer, WOTS_TW_CHAIN_COUNT1);

        for (uint32_t i = 0; i < WOTS_TW_CHAIN_COUNT2; i++)
        {
            out_buffer[WOTS_TW_CHAIN_COUNT1 + WOTS_TW_CHAIN_COUNT2 - 1 - i] = checksum % (1 << WOTS_TW_CHAIN_BITS);
            checksum >>= WOTS_TW_CHAIN_BITS;
        }
    }

    void wots_tw_pk_gen(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out)
    {
        unsigned char wots_sk[WOTS_TW_CHAIN_COUNT][N];

        unsigned char sk[N];
        for (uint32_t i = 0; i < WOTS_TW_CHAIN_COUNT; i++)
        {
            setType(adrs, SL_WOTS_TW_PRF);
            set_14_18(adrs, i);
            set_18_22(adrs, 0);

            prf(hash_ctx, sk_seed, adrs, sk);
            setType(adrs, SL_WOTS_TW_HASH);
            chain(sk, 0, (1 << WOTS_TW_CHAIN_BITS) - 1, hash_ctx, adrs, wots_sk[i]);
        }

        setType(adrs, SL_WOTS_TW_PK);
        set_14_22(adrs, 0);
        t_sl(hash_ctx, adrs, wots_sk[0], out);
    }

    void wots_tw_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out)
    {
        uint32_t indexes[WOTS_TW_CHAIN_COUNT];
        wots_tw_message_to_indexes(message, indexes);

        unsigned char sk[N];
        for (uint32_t i = 0; i < WOTS_TW_CHAIN_COUNT; i++)
        {
            setType(adrs, SL_WOTS_TW_PRF);
            set_14_18(adrs, i);
            set_18_22(adrs, 0);

            prf(hash_ctx, sk_seed, adrs, sk);
            setType(adrs, SL_WOTS_TW_HASH);
            chain(sk, 0, indexes[i], hash_ctx, adrs, out + N * i);
        }
    }

    void wots_tw_pk_from_sig(const unsigned char* sig, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out)
    {
        uint32_t indexes[WOTS_TW_CHAIN_COUNT];
        wots_tw_message_to_indexes(message, indexes);

        unsigned char wots_pk[WOTS_TW_CHAIN_COUNT][N];

        setType(adrs, SL_WOTS_TW_HASH);
        for (uint32_t i = 0; i < WOTS_TW_CHAIN_COUNT; i++)
        {
            set_14_18(adrs, i);
            uint32_t steps = (1 << WOTS_TW_CHAIN_BITS) - 1 - indexes[i];
            chain(sig + (i << 4), indexes[i], steps, hash_ctx, adrs, wots_pk[i]);
        }

        setType(adrs, SL_WOTS_TW_PK);
        set_14_22(adrs, 0);
        t_sl(hash_ctx, adrs, wots_pk[0], out);
    }

    void wots_c_pk_gen(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out)
    {
        unsigned char wots_sk[WOTS_C_CHAIN_COUNT][N];

        unsigned char sk[N];
        set_10_14(adrs, 0);
        for (uint32_t i = 0; i < WOTS_C_CHAIN_COUNT; i++)
        {
            setType(adrs, SF_WOTS_C_PRF);
            set_14_18(adrs, i);
            set_18_22(adrs, 0);

            prf(hash_ctx, sk_seed, adrs, sk);
            setType(adrs, SF_WOTS_C_HASH);
            chain(sk, 0, (1 << WOTS_C_CHAIN_BITS) - 1, hash_ctx, adrs, wots_sk[i]);
        }
        
        setType(adrs, SF_WOTS_C_PK);
        set_14_22(adrs, 0);
        t_sf(hash_ctx, adrs, wots_sk[0], out);
    }

    uint32_t wots_c_grind(const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, uint32_t* msg_out, bool* success)
    {
        unsigned char tmp[N];

        setType(adrs, SF_WOTS_C_GRIND);

        CSHA256 base_ctx = hash_ctx;
        sha256_add_to_ctx(base_ctx, adrs, 10);
        sha256_add_to_ctx(base_ctx, message, N << 1);
        sha256_add_to_ctx(base_ctx, zeros, 4);

        for (uint32_t i = 0; i <= UINT16_MAX; i++)
        {
            // h_grind(hash_ctx, adrs, message, i, tmp);

            unsigned char counter_be[2] = {
                static_cast<unsigned char>(i >> 8),
                static_cast<unsigned char>(i)
            };

            CSHA256 ctx = base_ctx;
            sha256_add_to_ctx(ctx, counter_be, 2);
            sha256_finalize(ctx, tmp);

            base_2b(tmp, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT, msg_out);
            if(sum(msg_out, WOTS_C_CHAIN_COUNT) == WOTS_C_CONSTANT_SUM)
            {
                *success = true;
                return i;
            }
        }
        
        *success = false;
        return 0;
    }

    bool wots_c_digest(const unsigned char* message, CSHA256& hash_ctx, uint32_t ctr, unsigned char* adrs, uint32_t* msg_out)
    {
        unsigned char tmp[N];
        setType(adrs, SF_WOTS_C_GRIND);
        h_grind(hash_ctx, adrs, message, ctr, tmp);
        base_2b(tmp, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT, msg_out);
        return sum(msg_out, WOTS_C_CHAIN_COUNT) == WOTS_C_CONSTANT_SUM;
    }

    bool wots_c_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out)
    {
        uint32_t indexes[WOTS_C_CHAIN_COUNT];
        bool success;
        uint32_t ctr = wots_c_grind(message, hash_ctx, adrs, indexes, &success);

        if (!success)
        {
            return false;
        }

        out[0] = static_cast<unsigned char>(ctr >> 8);
        out[1] = static_cast<unsigned char>(ctr);

        unsigned char sk[N];
        set_10_14(adrs, 0);
        for (uint32_t i = 0; i < WOTS_C_CHAIN_COUNT; i++)
        {
            setType(adrs, SF_WOTS_C_PRF);
            set_14_18(adrs, i);
            set_18_22(adrs, 0);
            prf(hash_ctx, sk_seed, adrs, sk);
            setType(adrs, SF_WOTS_C_HASH);
            chain(sk, 0, indexes[i], hash_ctx, adrs, out + N * i + 2);
        }

        return true;
    }

    bool wots_c_pk_from_sig(const unsigned char* sig, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out)
    {
        uint32_t ctr = (static_cast<uint32_t>(sig[0]) << 8) | sig[1];

        uint32_t indexes[WOTS_C_CHAIN_COUNT];
        if(!wots_c_digest(message, hash_ctx, ctr, adrs, indexes))
        {
            return false;
        }

        setType(adrs, SF_WOTS_C_HASH);
        set_10_14(adrs, 0);

        unsigned char wots_pk[WOTS_C_CHAIN_COUNT][N];

        for (uint32_t i = 0; i < WOTS_C_CHAIN_COUNT; i++)
        {
            set_14_18(adrs, i);
            chain(sig + 2 + N * i, indexes[i], (1 << WOTS_C_CHAIN_BITS) - 1 - indexes[i], hash_ctx, adrs, wots_pk[i]);
        }
        
        setType(adrs, SF_WOTS_C_PK);
        set_14_22(adrs, 0);
        t_sf(hash_ctx, adrs, wots_pk[0], out);

        return true;
    }
}