#include <iostream>
#include <chrono>
#include "shrincs.h"

using namespace std;
using namespace SHRINCS;

// Just leave it here, in case we want to print signatures in hex for debugging
void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

std::vector<unsigned char> hex_to_bytes(std::string hex) {
    // Видаляємо "0x", якщо він є
    if (hex.compare(0, 2, "0x") == 0) {
        hex = hex.substr(2);
    }

    if (hex.length() % 2 != 0) {
        throw std::runtime_error("Hex string must have an even length");
    }

    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

unsigned char hexCharToInt(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

void hexStringToBytes(const std::string& hex, unsigned char* buffer) {
    for (size_t i = 0; i < hex.length(); i += 2) {
        buffer[i / 2] = (hexCharToInt(hex[i]) << 4) | hexCharToInt(hex[i + 1]);
    }
}

int main() 
{
    SHA256AutoDetect();
    
    SecretKey sk = SecretKey();

    vector<unsigned char> structure, signature, opt_rand, cache;
    structure.push_back(0);
    structure.push_back(255);

    unsigned char seed[48];
    generate_random_bytes(seed, 48);

    auto start = std::chrono::high_resolution_clock::now();
    shrincs_keygen(seed, structure, sk, &cache);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    std::cout << "Keygen (unbalanced tree, 256 leafs): " << elapsed.count() << " ms" << std::endl;
    std::cout << std::endl;

    std::vector<unsigned char> message = std::vector<unsigned char>(32, 0);

    // hexStringToBytes("8a276ceb95d10ed7705c9e25c9987cb4b1eaf73bcae7f922058c4e46e906a778", message.data());

    start = std::chrono::high_resolution_clock::now();
    shrincs_sign(message, sk, 0, opt_rand, signature, &cache);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Stateful signing time: " << elapsed.count() << " ms" << std::endl;
    std::cout << "Stateful (state = 0) signature size: " << signature.size() << " bytes" << std::endl;

    // print_hex(signature.data(), signature.size());

    start = std::chrono::high_resolution_clock::now();
    bool is_valid = shrincs_verify(message, signature, sk.pk);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Stateful verification time: " << elapsed.count() << " ms" << std::endl;
    if (!is_valid) std::cout << "Error!" << std::endl;
    std::cout << std::endl;

    start = std::chrono::high_resolution_clock::now();
    shrincs_sign(message, sk, 255, opt_rand, signature, &cache);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Stateful signing time: " << elapsed.count() << " ms" << std::endl;
    std::cout << "Stateful (state = 255) signature size: " << signature.size() << " bytes" << std::endl;

    // print_hex(signature.data(), signature.size());

    start = std::chrono::high_resolution_clock::now();
    is_valid = shrincs_verify(message, signature, sk.pk);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Stateful verification time: " << elapsed.count() << " ms" << std::endl;
    if (!is_valid) std::cout << "Error!" << std::endl;
    std::cout << std::endl;

    start = std::chrono::high_resolution_clock::now();
    shrincs_sign(message, sk, 256, opt_rand, signature, &cache);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Stateless signing time: " << elapsed.count() << " ms" << std::endl;
    std::cout << "Stateless signature size: " << signature.size() << " bytes" << std::endl;

    // print_hex(signature.data(), signature.size());

    start = std::chrono::high_resolution_clock::now();
    is_valid = shrincs_verify(message, signature, sk.pk);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Stateless verification time: " << elapsed.count() << " ms" << std::endl;
    if (!is_valid) std::cout << "Error!" << std::endl;
    std::cout << std::endl;

    structure[0] = 1;
    structure[1] = 10;

    start = std::chrono::high_resolution_clock::now();
    shrincs_keygen(seed, structure, sk, &cache);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Keygen (balanced tree 2^10): " << elapsed.count() << " ms" << std::endl;
    std::cout << std::endl;

    start = std::chrono::high_resolution_clock::now();
    shrincs_sign(message, sk, 0, opt_rand, signature, &cache);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Stateful signing time: " << elapsed.count() << " ms" << std::endl;
    std::cout << "Stateful (state = 0, xmss) signature size: " << signature.size() << " bytes" << std::endl;

    // print_hex(signature.data(), signature.size());

    start = std::chrono::high_resolution_clock::now();
    is_valid = shrincs_verify(message, signature, sk.pk);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Stateful verification time: " << elapsed.count() << " ms" << std::endl;
    if (!is_valid) std::cout << "Error!" << std::endl;
    std::cout << std::endl;

    return 0;
}