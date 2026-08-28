#ifndef SHRINCS_H
#define SHRINCS_H

#include <random>
#include <vector>
#include "xmss.h"
#include "fxmss.h"
#include "fors.h"
#include "slh_dsa.h"

namespace SHRINCS {
    class PublicKey
    {
        public:
            std::vector<unsigned char> seed;
            std::vector<unsigned char> sl_root;
            std::vector<unsigned char> sf_root;

            PublicKey();
    };

    class SecretKey
    {
        public:
            std::vector<unsigned char> seed;
            std::vector<unsigned char> prf;
            std::vector<unsigned char> structure;
            PublicKey pk;

            SecretKey();
    };

    void generate_random_bytes(unsigned char* buffer, size_t length);

    bool shrincs_keygen(const std::vector<unsigned char>& seed, const std::vector<unsigned char>& structure, SecretKey& out_sk, std::vector<unsigned char>* out_cache = NULL, bool leaves_only = false);

    bool shrincs_sf_leaf_select(const std::vector<unsigned char>& structure, const uint64_t* state_ctr, uint64_t* out_lr, uint8_t* out_bt);
    bool shrincs_sign(const std::vector<unsigned char>& message, const std::vector<unsigned char>& ctx, const SecretKey& sk, const uint64_t* state_ctr, const std::vector<unsigned char>& opt_rand, std::vector<unsigned char>& out, std::vector<unsigned char>* cache = NULL, bool leaves_only = false);
    bool shrincs_verify(const std::vector<unsigned char>& message, const std::vector<unsigned char>& signature, const std::vector<unsigned char>& ctx, const PublicKey& pk);
}

#endif