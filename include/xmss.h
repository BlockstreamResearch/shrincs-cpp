#ifndef XMSS_H
#define XMSS_H

#include "wots.h"

using namespace WOTS;

namespace XMSS 
{
    void xmss_node(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t node_idx, uint32_t node_height, unsigned char* out);
    void xmss_sign(const unsigned char* message, const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t keypair_index, unsigned char* out);
    void xmss_pk_from_sig(const unsigned char* sig, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, uint32_t keypair_index, unsigned char* out);

}

#endif