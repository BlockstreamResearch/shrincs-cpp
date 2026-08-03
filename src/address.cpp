#include "address.h"

namespace Address 
{
    void setLayerAddress(unsigned char* adrs, uint8_t layer) 
    {
        memcpy(adrs, &layer, sizeof(layer));
    }

    void setTreeAddress(unsigned char* adrs, uint64_t tree_addr) 
    {
        tree_addr = htobe64(tree_addr);
        memcpy(adrs + 1, & tree_addr, sizeof(tree_addr));
    }

    void setType(unsigned char* adrs, uint8_t type)
    {
        memcpy(adrs + 9, &type, sizeof(type));
    }

    void set_10_14(unsigned char* adrs, uint32_t value) 
    {
        value = htobe32(value);
        memcpy(adrs + 10, &value, sizeof(value));
    }

    void set_14_18(unsigned char* adrs, uint32_t value) 
    {
        value = htobe32(value);
        memcpy(adrs + 14, &value, sizeof(value));
    }

    void set_14_22(unsigned char* adrs, uint64_t value)
    {
        value = htobe64(value);
        memcpy(adrs + 14, &value, sizeof(value));
    }

    void set_18_22(unsigned char* adrs, uint32_t value) 
    {
        value = htobe32(value);
        memcpy(adrs + 18, &value, sizeof(value));
    }
}