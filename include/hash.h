#ifndef HASH_H
#define HASH_H

#include "btc_sha/sha256.h"
#include <cstring>
#include <cmath>
#include <arpa/inet.h>
#include <algorithm>
#include "constants.h"

using namespace Parameters;

namespace HASH 
{
    void sha256_add_to_ctx(CSHA256& base_ctx, const unsigned char* data, size_t len);
    void sha256_finalize(CSHA256& base_ctx, unsigned char* out);
    void sha256_finalize_32(CSHA256& base_ctx, unsigned char* out);
    void prf_msg(const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* opt_rand, const unsigned char* message, uint32_t message_len, bool is_ctr, uint32_t ctr, uint32_t mask_len, unsigned char* out);
}

#endif