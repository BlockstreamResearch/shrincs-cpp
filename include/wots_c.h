#ifndef WOTS_C_H
#define WOTS_C_H

#include <array>
#include <vector>
#include <cmath>
#include <openssl/sha.h>
#include <stdexcept>
#include "address.h"
#include "constants.h"
#include "hash.h"

using namespace Parameters;
using namespace AddressTypes;
using namespace Address;
using namespace HASH;

namespace WOTS_C
{
    void base_w(const unsigned char* message, unsigned char* out_buffer);
    void chain(const unsigned char* m, uint32_t start, uint32_t steps, SHA256_CTX hash_ctx, unsigned char* adrs, unsigned char* out);
    unsigned char* wots_pk_gen(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t keypair, bool sf);
    uint32_t wots_grind(const unsigned char* message, unsigned char* adrs, unsigned char* msg_out);
    bool wots_digest(const unsigned char* message, uint32_t ctr, unsigned char* adrs, unsigned char* msg_out);
    unsigned char* wots_sign(const unsigned char* message, uint32_t message_len, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t keypair, bool sf, bool is_internal);
    unsigned char* wots_pk_from_sig(const unsigned char* sig, const unsigned char* message, uint32_t message_len, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t keypair, bool sf, bool is_internal);
}

#endif