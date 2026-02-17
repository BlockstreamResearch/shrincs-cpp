#include "address.h"

namespace Address 
{
    void setLayerAddress(unsigned char* adrs, uint32_t layer) 
    {
        layer = htonl(layer);
        memcpy(adrs, &layer, sizeof(layer));
    }

    void setTreeAddress(unsigned char* adrs, uint32_t tree_addr1, uint64_t tree_addr2) 
    {
        tree_addr1 = htonl(tree_addr1);
        tree_addr2 = htobe64(tree_addr2);

        memcpy(adrs + 4, &tree_addr1, sizeof(tree_addr1));
        memcpy(adrs + 8, &tree_addr2, sizeof(tree_addr2));
    }

    void setTypeAndClear(unsigned char* adrs, uint32_t type) 
    {
        type = htonl(type);
        memcpy(adrs + 16, &type, sizeof(type));
        memset(adrs + 20, 0, 12);
    }

    void setKeyPairAddress(unsigned char* adrs, uint32_t keypair) 
    {
        keypair = htonl(keypair);
        memcpy(adrs + 20, &keypair, sizeof(keypair));
    }

    void setChainAddress(unsigned char* adrs, uint32_t chain) 
    {
        chain = htonl(chain);
        memcpy(adrs + 24, &chain, sizeof(chain));
    }

    void setHashAddress(unsigned char* adrs, uint32_t hash) 
    {
        hash = htonl(hash);
        memcpy(adrs + 28, &hash, sizeof(hash));
    }

    void setTreeHeight(unsigned char* adrs, uint32_t height) 
    {
        height = htonl(height);
        memcpy(adrs + 24, &height, sizeof(height));
    }

    void setTreeIndex(unsigned char* adrs, uint32_t index) 
    {
        index = htonl(index);
        memcpy(adrs + 28, &index, sizeof(index));
    }
}