#ifndef ADDRESS_H
#define ADDRESS_H

#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

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