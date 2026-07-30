#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <cstdint>


#if !defined(SHRINCS_B) && !defined(SHRINCS_L) && !defined(SHRINCS_B32)
    #define SHRINCS_B32
#endif

namespace Parameters
{
    inline constexpr uint32_t WOTS_C_CHAIN_BITS = 4;
    inline constexpr uint32_t WOTS_C_CHAIN_COUNT = 32;
    inline constexpr uint32_t FXMSS_HEIGHT = 255;

    inline constexpr uint32_t N = 16;
    inline constexpr uint32_t WOTS_TW_CHAIN_BITS = 4;
    inline constexpr uint32_t WOTS_TW_CHAIN_COUNT1 = 32;
    inline constexpr uint32_t WOTS_TW_CHAIN_COUNT2 = 3;
    inline constexpr uint32_t WOTS_TW_CHAIN_COUNT = WOTS_TW_CHAIN_COUNT1 + WOTS_TW_CHAIN_COUNT2;
    inline constexpr uint32_t SPHX_LAYER_COUNT = 5;
    inline constexpr uint32_t SPHX_XMSS_HEIGHT = 9;
    inline constexpr uint32_t SPHX_FORS_HEIGHT = 13;
    inline constexpr uint32_t SPHX_FORS_COUNT = 10;

    inline constexpr uint32_t WOTS_C_CHAINS_SIZE = WOTS_C_CHAIN_COUNT << 4;
    inline constexpr uint32_t WOTS_C_CONSTANT_SUM = (WOTS_C_CHAIN_COUNT * ((1 << WOTS_C_CHAIN_BITS) - 1) + 1) >> 1;
    inline constexpr uint32_t FXMSS_SIGNATURE_SIZE_MIN = 2 + WOTS_C_CHAINS_SIZE + 16;
    inline constexpr uint32_t FXMSS_SIGNATURE_SIZE_MAX = 2 + WOTS_C_CHAINS_SIZE + 16 * FXMSS_HEIGHT;

    inline constexpr uint32_t WOTS_TW_CHAINS_SIZE = WOTS_TW_CHAIN_COUNT << 4;
    inline constexpr uint32_t WOTS_TW_CHECKSUM_MAX = WOTS_TW_CHAIN_COUNT1 * ((1 << WOTS_TW_CHAIN_BITS) - 1);
    inline constexpr uint32_t SPHX_XMSS_SIGNATURE_SIZE = WOTS_TW_CHAINS_SIZE + 16 * SPHX_XMSS_HEIGHT;
    inline constexpr uint32_t HYPERTREE_SIGNATURE_SIZE = SPHX_LAYER_COUNT * SPHX_XMSS_SIGNATURE_SIZE;
    inline constexpr uint32_t FORS_DIGEST_SIZE = (SPHX_FORS_COUNT * SPHX_FORS_HEIGHT + 7) >> 3;
    inline constexpr uint32_t FORS_SIGNATURE_SIZE = (SPHX_FORS_COUNT << 4) * (SPHX_FORS_HEIGHT + 1);
    inline constexpr uint32_t SPHX_SIGNATURE_SIZE = 16 + FORS_SIGNATURE_SIZE + HYPERTREE_SIGNATURE_SIZE;
    inline constexpr uint32_t SPHX_TREE_INDEX_BITS = SPHX_XMSS_HEIGHT * (SPHX_LAYER_COUNT - 1);
    inline constexpr uint32_t H = SPHX_LAYER_COUNT * SPHX_XMSS_HEIGHT;
    inline constexpr uint32_t M = ((SPHX_FORS_HEIGHT * SPHX_FORS_COUNT + 7) >> 3) + ((SPHX_XMSS_HEIGHT * (SPHX_LAYER_COUNT - 1) + 7) >> 3) + ((SPHX_XMSS_HEIGHT + 7) >> 3);

}

namespace AddressTypes
{
    inline constexpr uint32_t SL_WOTS_TW_HASH  = 0x00;
    inline constexpr uint32_t SL_WOTS_TW_PK  = 0x01;
    inline constexpr uint32_t SL_XMSS_TREE  = 0x02;
    inline constexpr uint32_t SL_FORS_TREE  = 0x03;
    inline constexpr uint32_t SL_FORS_ROOTS  = 0x04;
    inline constexpr uint32_t SL_WOTS_TW_PRF  = 0x05;
    inline constexpr uint32_t SL_FORS_PRF  = 0x06;
    inline constexpr uint32_t SF_WOTS_C_HASH  = 0x10;
    inline constexpr uint32_t SF_WOTS_C_PK  = 0x11;
    inline constexpr uint32_t SF_FXMSS_TREE  = 0x12;
    inline constexpr uint32_t SF_WOTS_C_PRF  = 0x15;
    inline constexpr uint32_t SF_WOTS_C_GRIND  = 0x16;

}

namespace FXMSSShape
{
    inline constexpr uint8_t FXMSS_SHAPE_UNBALANCED  = 0x00;
    inline constexpr uint8_t FXMSS_SHAPE_BALANCED  = 0x01;
}

#endif // CONSTANTS_H