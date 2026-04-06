#include <gtest/gtest.h>
#include "shrincs.h"

using namespace SHRINCS;

TEST(WOTSTest, SignVerify) {
    std::vector<unsigned char> message = std::vector<unsigned char>(32, 0);

    unsigned char sk_seed[N];
    unsigned char sk_prf[N];
    unsigned char pk_seed[N];
    unsigned char pk_root[N];
    unsigned char* adrs = new unsigned char[32]();

    SHA256_CTX hash_ctx;
    SHA256_Init(&hash_ctx);

    hash_ctx = sha256_add_to_ctx(hash_ctx, pk_seed, N);
    hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
    hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 16);

    auto signature = WOTS_C::wots_sign(message.data(), message.size(), sk_seed, sk_prf, pk_seed, pk_root, hash_ctx, adrs, 10, true, false);
    auto pkey = WOTS_C::wots_pk_from_sig(signature, message.data(), message.size(), pk_root, hash_ctx, adrs, 10, true, false);
    auto ex_pkey = WOTS_C::wots_pk_gen(sk_seed, hash_ctx, adrs, 10, true);

    EXPECT_TRUE((memcmp(pkey, ex_pkey, N) == 0));

    delete[] adrs;
    delete[] signature;
    delete[] pkey;
    delete[] ex_pkey;
}

TEST(XMSSTest, SignVerify) {
    std::vector<unsigned char> message = std::vector<unsigned char>(32, 0);

    unsigned char sk_seed[N];
    unsigned char sk_prf[N];
    unsigned char pk_seed[N];
    unsigned char pk_root[N];
    unsigned char* adrs = new unsigned char[32]();

    SHA256_CTX hash_ctx;
    SHA256_Init(&hash_ctx);

    hash_ctx = sha256_add_to_ctx(hash_ctx, pk_seed, N);
    hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
    hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 16);

    auto signature = XMSS::xmss_sign(message.data(), sk_seed, sk_prf, pk_seed, pk_root, hash_ctx, adrs, H_PRIME, 2);
    auto pkey = XMSS::xmss_pk_from_sig(signature, signature + WOTS_SIGN_LEN, message.data(), pk_root, hash_ctx, adrs, H_PRIME, 2);
    auto root = XMSS::xmss_root(sk_seed, hash_ctx, adrs, H_PRIME);

    EXPECT_TRUE((memcmp(pkey, root, N) == 0));

    delete[] adrs;
    delete[] signature;
    delete[] pkey;
    delete[] root;
}

TEST(UXMSSTest, SignVerify) {
    std::vector<unsigned char> message = std::vector<unsigned char>(32, 0);

    unsigned char sk_seed[N];
    unsigned char sk_prf[N];
    unsigned char pk_seed[N];
    unsigned char pk_root[N];
    unsigned char* adrs = new unsigned char[32]();

    SHA256_CTX hash_ctx;
    SHA256_Init(&hash_ctx);

    hash_ctx = sha256_add_to_ctx(hash_ctx, pk_seed, N);
    hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 32);
    hash_ctx = sha256_add_to_ctx(hash_ctx, adrs, 16);

    auto signature = UXMSS::uxmss_sign(message.data(), message.size(), sk_seed, sk_prf, pk_seed, pk_root, hash_ctx, adrs, 2);
    auto pkey = UXMSS::uxmss_pk_from_sig(signature, signature + WOTS_SIGN_LEN, message.data(), message.size(), pk_root, hash_ctx, adrs, 2);
    auto root = UXMSS::uxmss_root(sk_seed, hash_ctx, adrs);

    EXPECT_TRUE((memcmp(pkey, root, N) == 0));

    delete[] adrs;
    delete[] signature;
    delete[] pkey;
    delete[] root;
}

TEST(PORSTest, ExtractBits) {
    unsigned char* message = new unsigned char[16] {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // 1111111111111111111111 bin = 4194303 dec
    auto bits_22 = PORS_FP::extract_bits(message, 34, 22);
    EXPECT_EQ(bits_22, 4194303);

    bits_22 = PORS_FP::extract_bits(message, 35, 22);
    EXPECT_EQ(bits_22, 4194303);

    delete[] message;
}

TEST(SHRINCSTest, StatefulSignVerify) {
    PublicKey pk = PublicKey();
    SecretKey sk = SecretKey();
    State state = State();

    shrincs_key_gen(pk, sk, state);

    std::vector<unsigned char> message = std::vector<unsigned char>(32, 0);

    auto signature = shrincs_sign_stateful(message, sk, state);
    auto is_valid = shrincs_verify(message, signature, WOTS_SIGN_LEN + state.q * N + N, pk);

    EXPECT_TRUE(is_valid);

    delete[] signature;

    state.q = 10;
    signature = shrincs_sign_stateful(message, sk, state);
    is_valid = shrincs_verify(message, signature, WOTS_SIGN_LEN + state.q * N + N, pk);

    EXPECT_TRUE(is_valid);

    delete[] signature;

    state.q = 100;
    signature = shrincs_sign_stateful(message, sk, state);
    is_valid = shrincs_verify(message, signature, WOTS_SIGN_LEN + state.q * N + N, pk);

    EXPECT_TRUE(is_valid);

    delete[] signature;

    state.q = 189;
    signature = shrincs_sign_stateful(message, sk, state);
    is_valid = shrincs_verify(message, signature, WOTS_SIGN_LEN + (state.q - 1) * N + N, pk);

    EXPECT_TRUE(is_valid);

    delete[] signature;

    // Must fail
    state.q = 190;
    try
    {
        signature = shrincs_sign_stateful(message, sk, state);
        delete[] signature;
        EXPECT_TRUE(false);
    }
    catch(const std::exception& e)
    {
        // ...
    }
}

TEST(SHRINCSTest, StatelessSignVerify) {
    PublicKey pk = PublicKey();
    SecretKey sk = SecretKey();
    State state = State();

    shrincs_key_gen(pk, sk, state);

    std::vector<unsigned char> message = std::vector<unsigned char>(32, 0);

    auto signature = shrincs_sign_stateless(message, sk);
    bool is_valid = shrincs_verify(message, signature, SL_SIZE, pk);

    EXPECT_TRUE(is_valid);

    delete[] signature;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}