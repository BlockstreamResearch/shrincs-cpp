#ifndef FORS_C_H
#define FORS_C_H

#include <cmath>
#include <stdexcept>
#include <array>
#include "address.h"
#include "constants.h"
#include "hash.h"

using namespace Parameters;
using namespace AddressTypes;
using namespace Address;
using namespace HASH;

namespace FORS_C {
    uint32_t extract_bits(const unsigned char* message, uint32_t start_bit_idx, uint32_t bits_amount);
    void fors_msg_to_indices(const unsigned char* message, uint32_t* out_buffer);
    uint32_t fors_grind(const unsigned char* message, uint32_t message_len, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, unsigned char* adrs, uint32_t* out, unsigned char* digest_out, unsigned char* r_out);
    unsigned char* fors_sk_gen(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t tree_idx, uint32_t leaf_idx);
    unsigned char* fors_treehash(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t tree_idx, uint32_t target_height, uint32_t start_idx);
    unsigned char* fors_auth_path(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t tree_idx, uint32_t leaf_idx);
    unsigned char* fors_sign(const unsigned char* message, uint32_t message_len, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, unsigned char* digest_out);
    unsigned char* fors_pk_from_sig(const unsigned char* sig, uint32_t indices[K], SHA256_CTX hash_ctx, unsigned char* adrs);
}

#endif