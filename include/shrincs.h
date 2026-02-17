#ifndef SHRINCS_H
#define SHRINCS_H

#include <openssl/rand.h>
#include <vector>
#include "uxmss.h"
#include "xmss.h"
#include "fors_c.h"

namespace SHRINCS {
    class PublicKey
    {
        public:
            std::vector<unsigned char> seed;
            std::vector<unsigned char> root;

            PublicKey();
    };

    class SecretKey
    {
        public:
            std::vector<unsigned char> seed;
            std::vector<unsigned char> prf;
            std::vector<unsigned char> sf;
            std::vector<unsigned char> sl;
            PublicKey pk;

            SecretKey();
    };

    class State
    {
        public:
            uint32_t q;
            bool valid;

            State();
    };

    void generate_random_bytes(unsigned char* buffer, size_t length);
    void parse_idx(const unsigned char* digest, uint32_t* idx_tree, uint32_t* idx_leaf);

    void shrincs_key_gen(PublicKey& out_pk, SecretKey& out_sk, State& out_state);
    void shrincs_restore(const unsigned char* seed, PublicKey& out_pk, SecretKey& out_sk, State& out_state);
    unsigned char* shrincs_sign_stateful(const unsigned char* message, SecretKey& sk, State& state);
    unsigned char* shrincs_sign_stateless(const unsigned char* message, SecretKey& sk);
    bool shrincs_verify_stateful(const unsigned char* message, const unsigned char* sig, uint32_t sig_len, PublicKey& pk);
    bool shrincs_verify_stateless(const unsigned char* message, const unsigned char* sig, PublicKey& pk);
    bool shrincs_verify(const unsigned char* message, const unsigned char* sig, uint32_t sig_len, PublicKey& pk);
}

#endif