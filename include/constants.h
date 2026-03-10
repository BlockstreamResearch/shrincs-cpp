#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <cstdint>


#if !defined(SHRINCS_B) && !defined(SHRINCS_L)
    #define SHRINCS_B
#endif

namespace Parameters
{
    inline constexpr uint32_t N     = 16;   // Security parameter (bytes)
    inline constexpr uint32_t HSL   = 24;   // Max stateless hypertree height
    inline constexpr uint32_t D     = 2;    // Stateless hypertree layers
    inline constexpr uint32_t A     = 22;   // FORS tree height
    inline constexpr uint32_t K     = 6;    // Number of FORS+C trees
    inline constexpr uint32_t R_LEN = 32;   // Randomness length (bytes)

#if defined(SHRINCS_B)
    inline constexpr uint32_t W   = 256;    // Winternitz parameter
    inline constexpr uint32_t L   = 16;     // WOTS+C chain count
    inline constexpr uint32_t SWN = 2040;   // Target sum for WOTS+C
    inline constexpr uint32_t HSF = 158;    // Max stateful tree height
#else // SHRINCS_L
    inline constexpr uint32_t W   = 4;      
    inline constexpr uint32_t L   = 64;     
    inline constexpr uint32_t SWN = 140;    
    inline constexpr uint32_t HSF = 206;    
#endif

    inline constexpr uint32_t H_PRIME       = HSL / D;
    inline constexpr uint32_t WOTS_SIGN_LEN = R_LEN + 4 + L * N;
    inline constexpr uint32_t XMSS_SIGN_LEN = WOTS_SIGN_LEN + H_PRIME * N;
    inline constexpr uint32_t FORS_SIGN_LEN = R_LEN + (K - 1) * (A + 1) * N; // R + (K-1)*(A+1)*N
    inline constexpr uint32_t MAX_SF_SIZE   = N + WOTS_SIGN_LEN + HSF * N;
    inline constexpr uint32_t SL_SIZE       = N + FORS_SIGN_LEN + XMSS_SIGN_LEN * D;
}

namespace AddressTypes
{
    inline constexpr uint32_t SF_WOTS_HASH  = 0x00;
    inline constexpr uint32_t SF_WOTS_PK    = 0x01;
    inline constexpr uint32_t SF_TREE       = 0x02;
    inline constexpr uint32_t SF_WOTS_GRIND = 0x03;
    inline constexpr uint32_t SF_H_MSG      = 0x04;
    inline constexpr uint32_t SF_WOTS_PRF   = 0x05;
    inline constexpr uint32_t FORS_HASH     = 0x06;
    inline constexpr uint32_t FORS_TREE     = 0x07;
    inline constexpr uint32_t FORS_PK       = 0x08;
    inline constexpr uint32_t FORS_PRF      = 0x09;
    inline constexpr uint32_t SL_WOTS_HASH  = 0x0A;
    inline constexpr uint32_t SL_WOTS_PK    = 0x0B;
    inline constexpr uint32_t SL_TREE       = 0x0C;
    inline constexpr uint32_t SL_WOTS_GRIND = 0x0D;
    inline constexpr uint32_t SL_H_MSG      = 0x0E;
    inline constexpr uint32_t SL_WOTS_PRF   = 0x0F;
    inline constexpr uint32_t ROOT          = 0x10;
}

#endif // CONSTANTS_H