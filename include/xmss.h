#ifndef XMSS_H
#define XMSS_H

#include "wots_c.h"

using namespace WOTS_C;

namespace XMSS 
{
    unsigned char* xmss_treehash(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t target_height, uint32_t start_idx);
    unsigned char* xmss_root(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t h_prime);
    unsigned char* xmss_auth_path(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t h_prime, uint32_t idx);
    unsigned char* xmss_pk_from_sig(const unsigned char* wots_sig, const unsigned char* auth, const unsigned char* message, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t h_prime, uint32_t idx);
    unsigned char* xmss_sign(const unsigned char* message, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t h_prime, uint32_t idx);
}

#endif