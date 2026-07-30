#ifndef FXMSS_H
#define FXMSS_H

#include "wots.h"
#include <algorithm>

using namespace WOTS;
using namespace FXMSSShape;

namespace FXMSS 
{
    bool fxmss_node(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, const unsigned char* structure, uint64_t node_index, uint32_t node_height, unsigned char* out);
    bool fxmss_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, uint64_t leaf_index, uint32_t leaf_height, const unsigned char* structure, unsigned char* out);
    bool fxmss_pk_from_sig(const unsigned char* sig, uint32_t sig_len, const unsigned char* message, CSHA256& hash_ctx, uint64_t leaf_index, unsigned char* out);
}

#endif