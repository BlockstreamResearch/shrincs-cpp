#ifndef PORS_FP_H
#define PORS_FP_H

#include <cmath>
#include <stdexcept>
#include <array>
#include <tuple>
#include <vector>
#include <algorithm>
#include <atomic>
#include <thread>
#include "address.h"
#include "constants.h"
#include "hash.h"

using namespace Parameters;
using namespace AddressTypes;
using namespace Address;
using namespace HASH;

namespace PORS_FP {
    uint32_t extract_bits(const unsigned char* message, uint32_t start_bit_idx, uint32_t bits_amount);
    bool uint32_arr_have(uint32_t* arr, uint32_t arr_size, uint32_t elem);
    unsigned char* pors_msg_to_indices(const unsigned char* message, unsigned char* adrs, SHA256_CTX hash_ctx, uint32_t* indices_out, unsigned char* xof_out);
    bool pors_octopus(uint32_t* indices, std::tuple<uint32_t, uint32_t>* A_out, uint32_t& A_len_out);
    void pors_grind(const unsigned char* message, uint32_t message_len, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, unsigned char* adrs, unsigned char* opt_rand, SHA256_CTX hash_ctx, uint32_t* indices_out, unsigned char* digest_out, unsigned char* r_out);
    unsigned char* pors_sk_gen(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t leaf_idx);
    unsigned char* pors_treehash(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t target_height, uint32_t idx);
    unsigned char* pors_auth_path(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t* indices);
    unsigned char* pors_sign(const unsigned char* message, uint32_t message_len, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, unsigned char* digest_out);
    unsigned char* pors_pk_from_sig(const unsigned char* sig, uint32_t indices[K], SHA256_CTX hash_ctx, unsigned char* adrs);
}

#endif