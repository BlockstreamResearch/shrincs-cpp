#ifndef SLH_DSA_H
#define SLH_DSA_H

#include "ht.h"
#include "fors.h"

using namespace HT;
using namespace FORS;

namespace SLH_DSA
{
    void slh_dsa_digest_message(const unsigned char* r, const unsigned char* pk_seed, const unsigned char* sl_root, const unsigned char* message, uint32_t m_len, unsigned char* out_digest, uint64_t* out_tree, uint32_t* out_leaf);
    void slh_dsa_sign_internal(const unsigned char* message, uint32_t m_len, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* sl_root, const unsigned char* opt_rand, unsigned char* out);
    bool slh_dsa_verify_internal(const unsigned char* message, uint32_t m_len, const unsigned char* signature, const unsigned char* pk_seed, const unsigned char* sl_root);
    bool slh_dsa_sign(const unsigned char* message, uint32_t m_len, const unsigned char* ctx, uint32_t ctx_len, const unsigned char* sk_seed, const unsigned char* sk_prf, const unsigned char* pk_seed, const unsigned char* sl_root, const unsigned char* opt_rand, unsigned char* out);
    bool slh_dsa_verify(const unsigned char* message, uint32_t m_len, const unsigned char* signature, const unsigned char* ctx, uint32_t ctx_len, const unsigned char* pk_seed, const unsigned char* sl_root);
}

#endif