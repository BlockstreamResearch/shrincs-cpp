#ifndef HASH_H
#define HASH_H

#include <openssl/sha.h>
#include <cstring>
#include <cmath>
#include <arpa/inet.h>
#include "constants.h"

using namespace Parameters;

namespace HASH 
{
    SHA256_CTX sha256_add_to_ctx(const SHA256_CTX& base_ctx, const unsigned char* data, size_t len);
    void sha256_finalize(const SHA256_CTX& base_ctx, unsigned char* out);
    void sha256_finalize_32(const SHA256_CTX& base_ctx, unsigned char* out);
    unsigned char* prf_msg(const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* opt_rand, const unsigned char* message, uint32_t message_len, uint32_t mask_len);
}

#endif