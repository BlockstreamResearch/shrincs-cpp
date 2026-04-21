#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <cstdint>


#if !defined(SHRINCS_B) && !defined(SHRINCS_L) && !defined(SHRINCS_B32)
    #define SHRINCS_B32
#endif

namespace Parameters
{
    inline constexpr uint32_t N     = 16;         // Security parameter (bytes)
    inline constexpr uint32_t R_LEN = 32;         // Randomness length (bytes)

#if defined(SHRINCS_B)
    inline constexpr uint32_t W      = 256;          // Winternitz parameter
    inline constexpr uint32_t L      = 16;           // WOTS+C chain count
    inline constexpr uint32_t SWN    = 2040;         // Target sum for WOTS+C
    inline constexpr uint32_t HSF    = 141;          // Max stateful tree height
    inline constexpr uint32_t HSL    = 24;           // Max stateless hypertree height
    inline constexpr uint32_t D      = 2;            // Stateless hypertree layers
    inline constexpr uint32_t T      = 9245141;      // The number of secret values in PORS+FP tree
    inline constexpr uint32_t B      = 24;           // PORS+FP tree height
    inline constexpr uint32_t K      = 6;            // Number of PORS+FP revealed tree leafs
    inline constexpr uint32_t M_MAX  = 91;           // Maximum size of the Octopus authentication path
    inline constexpr uint32_t margin = 7;
#elif defined(SHRINCS_B32)
    inline constexpr uint32_t W      = 256;
    inline constexpr uint32_t L      = 16;
    inline constexpr uint32_t SWN    = 2040;
    inline constexpr uint32_t HSF    = 210;
    inline constexpr uint32_t HSL    = 32;
    inline constexpr uint32_t D      = 4;
    inline constexpr uint32_t T      = 109571;
    inline constexpr uint32_t B      = 17;
    inline constexpr uint32_t K      = 11;
    inline constexpr uint32_t M_MAX  = 111;
    inline constexpr uint32_t margin = 10;
#else // SHRINCS_L
    inline constexpr uint32_t W      = 4;      
    inline constexpr uint32_t L      = 64;     
    inline constexpr uint32_t SWN    = 140;    
    inline constexpr uint32_t HSF    = 189;   
    inline constexpr uint32_t HSL    = 24;
    inline constexpr uint32_t D      = 2;
    inline constexpr uint32_t T      = 9245141;
    inline constexpr uint32_t B      = 24;
    inline constexpr uint32_t K      = 6;
    inline constexpr uint32_t M_MAX  = 91;
    inline constexpr uint32_t margin = 7;
#endif

    inline constexpr uint32_t H_PRIME       = HSL / D;
    inline constexpr uint32_t WOTS_SIGN_LEN = R_LEN + 4 + L * N;
    inline constexpr uint32_t XMSS_SIGN_LEN = WOTS_SIGN_LEN + H_PRIME * N;
    inline constexpr uint32_t PORS_SIGN_LEN = R_LEN + (K + M_MAX) * N;
    inline constexpr uint32_t MAX_SF_SIZE   = N + WOTS_SIGN_LEN + HSF * N;
    inline constexpr uint32_t SL_SIZE       = N + PORS_SIGN_LEN + XMSS_SIGN_LEN * D;

    // PORS additional constants
    inline constexpr uint32_t c = 256 / B;
    inline constexpr uint32_t xof_offset_bits = (((1 << B) * K + T - 1) / T + margin) * B + 16;
    inline constexpr uint32_t xof_block_idx = (xof_offset_bits + 32 + 255) >> 8;
}

namespace AddressTypes
{
    inline constexpr uint32_t SF_WOTS_HASH  = 0x00;
    inline constexpr uint32_t SF_WOTS_PK    = 0x01;
    inline constexpr uint32_t SF_TREE       = 0x02;
    inline constexpr uint32_t SF_WOTS_GRIND = 0x03;
    inline constexpr uint32_t SF_H_MSG      = 0x04;
    inline constexpr uint32_t SF_WOTS_PRF   = 0x05;
    inline constexpr uint32_t PORS_HASH     = 0x06;
    inline constexpr uint32_t PORS_TREE     = 0x07;
    inline constexpr uint32_t PORS_PK       = 0x08;
    inline constexpr uint32_t PORS_PRF      = 0x09;
    inline constexpr uint32_t PORS_XOF      = 0x0A;
    inline constexpr uint32_t SL_WOTS_HASH  = 0x0B;
    inline constexpr uint32_t SL_WOTS_PK    = 0x0C;
    inline constexpr uint32_t SL_TREE       = 0x0D;
    inline constexpr uint32_t SL_WOTS_GRIND = 0x0E;
    inline constexpr uint32_t SL_H_MSG      = 0x0F;
    inline constexpr uint32_t SL_WOTS_PRF   = 0x10;
    inline constexpr uint32_t ROOT          = 0x11;
}

#endif // CONSTANTS_H