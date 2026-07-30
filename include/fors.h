#ifndef FORS_H
#define FORS_H

#include "address.h"
#include "constants.h"
#include "hash.h"
#include "wots.h"

using namespace Parameters;
using namespace AddressTypes;
using namespace Address;
using namespace HASH;

namespace FORS 
{
    void fors_sk_gen(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t node_index, unsigned char* out);
    void fors_node(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char* adrs, uint32_t node_index, uint32_t node_height, unsigned char* out);
    void fors_sign(const unsigned char* sk_seed, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out);
    void fors_pk_from_sig(const unsigned char* sig, const unsigned char* message, CSHA256& hash_ctx, unsigned char* adrs, unsigned char* out);
}

#endif