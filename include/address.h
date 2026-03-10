#ifndef ADDRESS_H
#define ADDRESS_H

#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

#ifdef __APPLE__
    #include <machine/endian.h>
    #include <libkern/OSByteOrder.h>
    #define htobe64(x) OSSwapHostToBigInt64(x)
    #define htobe32(x) OSSwapHostToBigInt32(x)
    #define be64toh(x) OSSwapBigToHostInt64(x)
    #define be32toh(x) OSSwapBigToHostInt32(x)
#else
    #include <endian.h>
#endif

namespace Address 
{
    void setLayerAddress(unsigned char* adrs, uint32_t layer);
    void setTreeAddress(unsigned char* adrs, uint32_t tree_addr1, uint64_t tree_addr2);
    void setTypeAndClear(unsigned char* adrs, uint32_t type);
    void setKeyPairAddress(unsigned char* adrs, uint32_t keypair);
    void setChainAddress(unsigned char* adrs, uint32_t chain);
    void setHashAddress(unsigned char* adrs, uint32_t hash);
    void setTreeHeight(unsigned char* adrs, uint32_t height);
    void setTreeIndex(unsigned char* adrs, uint32_t index);
}

#endif