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
    PublicKey pk = PublicKey();
    SecretKey sk = SecretKey();
    State state = State();

    shrincs_key_gen(pk, sk, state);
    // pk.seed = hex_to_bytes("29ab27ec700ca13c532563d0a0708a0c");
    // pk.root = hex_to_bytes("4bdcaf7f38409293a679e189f517b8ba");

    // memcpy(sk.pk.seed.data(), pk.seed.data(), N);
    // memcpy(sk.pk.root.data(), pk.root.data(), N);
    // sk.sf = hex_to_bytes("967fef422d4dc6c9bc7ca0cac3e1185b");
    // sk.sl = hex_to_bytes("95e85f3d7035d4a0cf780eb661bee1b9");
    // sk.prf = hex_to_bytes("c522c648c2ec264290a5e2daf5a3516d");
    // sk.seed = hex_to_bytes("46cfcaae59053efb09a25e99affb3d86");

    // state.q = 0;
    // state.valid = true;

    // print_hex(pk.seed.data(), N);
    // print_hex(pk.root.data(), N);
    // print_hex(sk.sf.data(), N);
    // print_hex(sk.sl.data(), N);
    // print_hex(sk.prf.data(), N);
    // print_hex(sk.seed.data(), N);

    unsigned char* message = new unsigned char[32]();

    // hexStringToBytes("8a276ceb95d10ed7705c9e25c9987cb4b1eaf73bcae7f922058c4e46e906a778", message);

    auto start = std::chrono::high_resolution_clock::now();
    auto signature = shrincs_sign_stateful(message, sk, state);
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    std::cout << "Stateful signing time: " << elapsed.count() << " ms" << std::endl;

    // print_hex(signature, N + WOTS_SIGN_LEN + state.q * N);

    start = std::chrono::high_resolution_clock::now();
    bool is_valid = shrincs_verify(message, signature, WOTS_SIGN_LEN + state.q * N + N, pk);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Stateful verification time: " << elapsed.count() << " ms" << std::endl;
    if (!is_valid) std::cout << "Error!" << std::endl;
    delete[] signature;

    start = std::chrono::high_resolution_clock::now();
    signature = shrincs_sign_stateless(message, sk);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Stateless signing time: " << elapsed.count() << " ms" << std::endl;

    // print_hex(signature, SL_SIZE);

    start = std::chrono::high_resolution_clock::now();
    is_valid = shrincs_verify(message, signature, SL_SIZE, pk);
    end = std::chrono::high_resolution_clock::now();
    elapsed = end - start;
    std::cout << "Stateless verification time: " << elapsed.count() << " ms" << std::endl;
    delete[] signature;
    if (!is_valid) std::cout << "Error!" << std::endl;

    return 0;
}