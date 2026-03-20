#ifndef UXMSS_H
#define UXMSS_H

#include "wots_c.h"

using namespace WOTS_C;

namespace UXMSS 
{
    unsigned char* uxmss_treehash(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t level);
    unsigned char* uxmss_root(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs);
    unsigned char* uxmss_auth_path(const unsigned char* sk_seed, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t q);
    unsigned char* uxmss_pk_from_sig(const unsigned char* wots_sig, const unsigned char* auth, const unsigned char* message, uint32_t message_len, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t q);
    unsigned char* uxmss_sign(const unsigned char* message, uint32_t message_len, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* pk_root, SHA256_CTX hash_ctx, unsigned char* adrs, uint32_t q);
}

#endif