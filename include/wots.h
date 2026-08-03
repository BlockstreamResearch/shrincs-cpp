#ifndef WOTS_H
#define WOTS_H

#include "address.h"
#include "constants.h"
#include "hash.h"

using namespace Parameters;
using namespace AddressTypes;
using namespace Address;
using namespace HASH;

namespace WOTS
{
    uint32_t sum(const uint32_t* arr, uint32_t arr_len);
    void base_2b(const unsigned char* message, uint32_t b, uint32_t outlen, uint32_t* out_buffer);
    void chain(const unsigned char* m, uint32_t start, uint32_t steps, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out);

    void wots_tw_message_to_indexes(const unsigned char* message, uint32_t* out_buffer);
    void wots_tw_pk_gen(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out);
    void wots_tw_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out);
    void wots_tw_pk_from_sig(const unsigned char* sig, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out);

    void wots_c_pk_gen(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out);
    uint32_t wots_c_grind(const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, uint32_t* msg_out, bool* success);
    bool wots_c_digest(const unsigned char* message, CSHA256& hash_ctx, uint32_t ctr, unsigned char* adrs, uint32_t* msg_out);
    bool wots_c_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out);
    bool wots_c_pk_from_sig(const unsigned char* sig, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out);
}

#endif