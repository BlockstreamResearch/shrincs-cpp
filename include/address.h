#ifndef ADDRESS_H
#define ADDRESS_H

#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

namespace Address 
{
    void setLayerAddress(unsigned char* adrs, uint8_t layer);
    void setTreeAddress(unsigned char* adrs, uint64_t tree_addr);
    void setType(unsigned char* adrs, uint8_t type);
    void set_10_14(unsigned char* adrs, uint32_t value);
    void set_14_18(unsigned char* adrs, uint32_t value);
    void set_14_22(unsigned char* adrs, uint64_t value);
    void set_18_22(unsigned char* adrs, uint32_t value);
}

#endif