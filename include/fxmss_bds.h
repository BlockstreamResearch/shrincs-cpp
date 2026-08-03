#ifndef FXMSS_BDS_H
#define FXMSS_BDS_H

#include "wots.h"

namespace BDS
{
    uint64_t state_size(unsigned char tree_depth);
    bool init(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char tree_depth, unsigned char* state, unsigned char* out_root);
    bool auth_path(const unsigned char* state, unsigned char tree_depth, uint64_t leaf_index, unsigned char* out);
    bool advance(const unsigned char* sk_seed, CSHA256& hash_ctx, unsigned char tree_depth, unsigned char* state);
}

#endif
