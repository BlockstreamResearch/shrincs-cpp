#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <cstdint>

namespace Parameters 
{
    inline constexpr uint32_t N = 16; // Security parameter (bytes)
    inline constexpr uint32_t W = 4; // Winternitz parameter
    inline constexpr uint32_t L = 64; // WOTS+C chain amount
    inline constexpr uint32_t SWN = 140; // Target sum for WOTS+C
    inline constexpr uint32_t HSF = 205; // Max stateful tree height
    inline constexpr uint32_t HSL = 24; // Max stateless hypertree height
    inline constexpr uint32_t D = 2; // Stateless hypertree layers
    inline constexpr uint32_t A = 22; // FORS tree height
    inline constexpr uint32_t K = 6; // Number of FORS+C trees (actually in +c we only need K - 1 trees)
    inline constexpr uint32_t R_LEN = 32; // Randomness len (bytes)

    inline constexpr uint32_t H_PRIME = HSL / D;
    inline constexpr uint32_t WOTS_SIGN_LEN = R_LEN + 4 + L * N;
    inline constexpr uint32_t XMSS_SIGN_LEN = WOTS_SIGN_LEN + H_PRIME * N;
    // R + ctr + (K - 1)*(A + 1)
    inline constexpr uint32_t FORS_SIGN_LEN = R_LEN + 4 + (K - 1)*(A + 1)*N;
    inline constexpr uint32_t MAX_SF_SIZE = N + WOTS_SIGN_LEN + HSF * N;
}

namespace AddressTypes 
{
    inline constexpr uint32_t SF_WOTS_HASH = 0x0;
    inline constexpr uint32_t SF_WOTS_PK = 0x1;
    inline constexpr uint32_t SF_TREE = 0x2;
    inline constexpr uint32_t SL_WOTS_HASH = 0x3;
    inline constexpr uint32_t SL_WOTS_PK = 0x4;
    inline constexpr uint32_t SL_TREE = 0x5;
    inline constexpr uint32_t FORS_HASH = 0x6;
    inline constexpr uint32_t FORS_TREE = 0x7;
    inline constexpr uint32_t FORS_PK = 0x8;
    inline constexpr uint32_t WOTS_GRIND = 0x9;
    inline constexpr uint32_t FORS_GRIND = 0x0A;
    inline constexpr uint32_t H_MSG = 0x0B;
    inline constexpr uint32_t WOTS_PRF = 0x0C;
    inline constexpr uint32_t FORS_PRF = 0x0D;
    inline constexpr uint32_t ROOT = 0x0E;
}

#endif