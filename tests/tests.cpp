#include <gtest/gtest.h>
#include <string>
#include "shrincs.h"

using namespace SHRINCS;

namespace {

const std::vector<unsigned char> STRUCTURE_BALANCED = {FXMSS_SHAPE_BALANCED, 4};
const std::vector<unsigned char> STRUCTURE_UNBALANCED = {FXMSS_SHAPE_UNBALANCED, 16};

std::vector<unsigned char> test_seed(unsigned char salt)
{
    std::vector<unsigned char> seed(3 * N);
    for (size_t i = 0; i < seed.size(); i++)
    {
        seed[i] = static_cast<unsigned char>(i * 7 + salt);
    }

    return seed;
}

CSHA256 midstate(const unsigned char* pk_seed)
{
    CSHA256 ctx;
    sha256_add_to_ctx(ctx, pk_seed, N);
    sha256_add_to_ctx(ctx, zeros, 64 - N);

    return ctx;
}

// Key generation walks the whole 512-leaf stateless tree, so each structure is
// generated once and shared by every test that needs it.
const SecretKey& keypair(const std::vector<unsigned char>& structure, unsigned char salt)
{
    static SecretKey balanced;
    static SecretKey unbalanced;
    static bool balanced_ready = false;
    static bool unbalanced_ready = false;

    bool is_balanced = structure[0] == FXMSS_SHAPE_BALANCED;
    SecretKey& sk = is_balanced ? balanced : unbalanced;
    bool& ready = is_balanced ? balanced_ready : unbalanced_ready;

    if (!ready)
    {
        std::vector<unsigned char> seed = test_seed(salt);
        EXPECT_TRUE(shrincs_keygen(seed.data(), structure, sk));
        ready = true;
    }

    return sk;
}

const SecretKey& balanced_key() { return keypair(STRUCTURE_BALANCED, 0x00); }
const SecretKey& unbalanced_key() { return keypair(STRUCTURE_UNBALANCED, 0x40); }

uint32_t stateful_sig_size(uint8_t leaf_height)
{
    return N + 8 + 2 + WOTS_C_CHAINS_SIZE + N * (FXMSS_HEIGHT - leaf_height);
}

std::string to_hex(const unsigned char* data, size_t len)
{
    static const char digits[] = "0123456789abcdef";

    std::string out;
    out.reserve(len << 1);
    for (size_t i = 0; i < len; i++)
    {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }

    return out;
}

// Signatures run to several kilobytes, so the vectors below pin their digest.
std::string sha256_hex(const std::vector<unsigned char>& data)
{
    unsigned char digest[32];
    CSHA256 ctx;
    sha256_add_to_ctx(ctx, data.data(), data.size());
    sha256_finalize_32(ctx, digest);

    return to_hex(digest, 32);
}

}

TEST(HashTest, HmacSha256MatchesRfc4231) {
    // RFC 4231, test case 2.
    const unsigned char key[] = {'J', 'e', 'f', 'e'};
    const char* message = "what do ya want for nothing?";

    const unsigned char expected[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };

    unsigned char out[32];
    hmac_sha256(key, sizeof(key), reinterpret_cast<const unsigned char*>(message), strlen(message), out);

    EXPECT_EQ(0, memcmp(out, expected, 32));
}

TEST(HashTest, HmacSha256MatchesRfc4231FullBlockKey) {
    // RFC 4231, test case 1 uses a 20-byte key; exercise the zero padding path.
    const unsigned char key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const char* message = "Hi There";

    const unsigned char expected[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };

    unsigned char out[32];
    hmac_sha256(key, sizeof(key), reinterpret_cast<const unsigned char*>(message), strlen(message), out);

    EXPECT_EQ(0, memcmp(out, expected, 32));
}

TEST(WOTSTest, Base2bSplitsNibbles) {
    const unsigned char message[2] = {0x12, 0x34};

    uint32_t out[4];
    WOTS::base_2b(message, 4, 4, out);

    EXPECT_EQ(1u, out[0]);
    EXPECT_EQ(2u, out[1]);
    EXPECT_EQ(3u, out[2]);
    EXPECT_EQ(4u, out[3]);
}

TEST(WOTSTest, Base2bHandlesForsWidth) {
    // FORS indexes are 13 bits wide and must not be truncated to a byte.
    const unsigned char message[4] = {0xff, 0xff, 0xff, 0xff};

    uint32_t out[2];
    WOTS::base_2b(message, SPHX_FORS_HEIGHT, 2, out);

    EXPECT_EQ(8191u, out[0]);
    EXPECT_EQ(8191u, out[1]);
}

TEST(WOTSTest, MessageToIndexesIsChecksummed) {
    unsigned char message[N];
    memset(message, 0xff, N);

    uint32_t indexes[WOTS_TW_CHAIN_COUNT];
    WOTS::wots_tw_message_to_indexes(message, indexes);

    // An all-ones message maxes out every chain, so the checksum is zero.
    for (uint32_t i = 0; i < WOTS_TW_CHAIN_COUNT1; i++)
    {
        EXPECT_EQ((1u << WOTS_TW_CHAIN_BITS) - 1, indexes[i]);
    }
    for (uint32_t i = WOTS_TW_CHAIN_COUNT1; i < WOTS_TW_CHAIN_COUNT; i++)
    {
        EXPECT_EQ(0u, indexes[i]);
    }
}

TEST(AddressTest, SetTypeKeepsPayload) {
    // The ADRS payload holds the keypair index for the SL_WOTS_TW_* types, so
    // setting the type byte must not clear bytes 10..22.
    unsigned char adrs[22] = {0};
    set_10_14(adrs, 0x01020304);
    set_14_18(adrs, 0x05060708);
    set_18_22(adrs, 0x090a0b0c);

    setType(adrs, SL_WOTS_TW_PRF);

    EXPECT_EQ(SL_WOTS_TW_PRF, adrs[9]);
    const unsigned char expected[12] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    EXPECT_EQ(0, memcmp(adrs + 10, expected, 12));
}

TEST(AddressTest, TreeAddressIsBigEndian) {
    unsigned char adrs[22] = {0};
    setTreeAddress(adrs, UINT64_C(0x0102030405060708));

    const unsigned char expected[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    EXPECT_EQ(0, memcmp(adrs + 1, expected, 8));
}

TEST(WOTSTest, WotsTwRecoversPublicKey) {
    std::vector<unsigned char> seed = test_seed(0x11);
    const unsigned char* sk_seed = seed.data();
    const unsigned char* pk_seed = seed.data() + 2 * N;

    CSHA256 hash_ctx = midstate(pk_seed);

    unsigned char message[N];
    memset(message, 0xa5, N);

    unsigned char base[22] = {0};
    setLayerAddress(base, SPHX_LAYER_COUNT - 1);
    setTreeAddress(base, 7);
    set_10_14(base, 3);

    unsigned char adrs[22], sig[WOTS_TW_CHAINS_SIZE], from_sig[N], generated[N];

    memcpy(adrs, base, 22);
    WOTS::wots_tw_sign(message, sk_seed, hash_ctx, adrs, sig);

    memcpy(adrs, base, 22);
    WOTS::wots_tw_pk_from_sig(sig, message, hash_ctx, adrs, from_sig);

    memcpy(adrs, base, 22);
    WOTS::wots_tw_pk_gen(sk_seed, hash_ctx, adrs, generated);

    EXPECT_EQ(0, memcmp(from_sig, generated, N));
}

TEST(WOTSTest, WotsCRecoversPublicKey) {
    std::vector<unsigned char> seed = test_seed(0x22);
    const unsigned char* sk_seed = seed.data();
    const unsigned char* pk_seed = seed.data() + 2 * N;

    CSHA256 hash_ctx = midstate(pk_seed);

    unsigned char digest[N << 1];
    memset(digest, 0x5a, N << 1);

    unsigned char base[22] = {0};
    setLayerAddress(base, 200);
    setTreeAddress(base, 1);

    unsigned char adrs[22], sig[2 + WOTS_C_CHAINS_SIZE], from_sig[N], generated[N];

    memcpy(adrs, base, 22);
    ASSERT_TRUE(WOTS::wots_c_sign(digest, sk_seed, hash_ctx, adrs, sig));

    memcpy(adrs, base, 22);
    ASSERT_TRUE(WOTS::wots_c_pk_from_sig(sig, digest, hash_ctx, adrs, from_sig));

    memcpy(adrs, base, 22);
    WOTS::wots_c_pk_gen(sk_seed, hash_ctx, adrs, generated);

    EXPECT_EQ(0, memcmp(from_sig, generated, N));
}

TEST(WOTSTest, WotsCGrindHitsConstantSum) {
    std::vector<unsigned char> seed = test_seed(0x33);
    CSHA256 hash_ctx = midstate(seed.data() + 2 * N);

    unsigned char digest[N << 1];
    memset(digest, 0x77, N << 1);

    unsigned char adrs[22] = {0};
    setLayerAddress(adrs, 128);

    uint32_t indexes[WOTS_C_CHAIN_COUNT];
    bool success = false;
    uint32_t counter = WOTS::wots_c_grind(digest, hash_ctx, adrs, indexes, &success);

    ASSERT_TRUE(success);
    EXPECT_LE(counter, 0xFFFFu);
    EXPECT_EQ(WOTS_C_CONSTANT_SUM, WOTS::sum(indexes, WOTS_C_CHAIN_COUNT));

    // The counter the signer emits must reproduce the same index set.
    uint32_t replayed[WOTS_C_CHAIN_COUNT];
    unsigned char verify_adrs[22] = {0};
    setLayerAddress(verify_adrs, 128);
    ASSERT_TRUE(WOTS::wots_c_digest(digest, hash_ctx, counter, verify_adrs, replayed));
    EXPECT_EQ(0, memcmp(indexes, replayed, sizeof(indexes)));
}

TEST(XMSSTest, RecoversRoot) {
    std::vector<unsigned char> seed = test_seed(0x44);
    const unsigned char* sk_seed = seed.data();
    const unsigned char* pk_seed = seed.data() + 2 * N;

    CSHA256 hash_ctx = midstate(pk_seed);

    unsigned char message[N];
    memset(message, 0x3c, N);

    const uint32_t leaf = 5;

    unsigned char base[22] = {0};
    setLayerAddress(base, 0);
    setTreeAddress(base, 2);

    unsigned char adrs[22], sig[SPHX_XMSS_SIGNATURE_SIZE], from_sig[N], root[N];

    memcpy(adrs, base, 22);
    XMSS::xmss_sign(message, sk_seed, hash_ctx, adrs, leaf, sig);

    memcpy(adrs, base, 22);
    XMSS::xmss_pk_from_sig(sig, message, hash_ctx, adrs, leaf, from_sig);

    memcpy(adrs, base, 22);
    XMSS::xmss_node(sk_seed, hash_ctx, adrs, 0, SPHX_XMSS_HEIGHT, root);

    EXPECT_EQ(0, memcmp(from_sig, root, N));
}

TEST(FORSTest, RecoversPublicKeyAndRejectsTampering) {
    std::vector<unsigned char> seed = test_seed(0x55);
    const unsigned char* sk_seed = seed.data();
    const unsigned char* pk_seed = seed.data() + 2 * N;

    CSHA256 hash_ctx = midstate(pk_seed);

    unsigned char digest[FORS_DIGEST_SIZE];
    for (uint32_t i = 0; i < FORS_DIGEST_SIZE; i++)
    {
        digest[i] = static_cast<unsigned char>(i * 11 + 3);
    }

    unsigned char base[22] = {0};
    setTreeAddress(base, 9);
    set_10_14(base, 4);

    std::vector<unsigned char> sig(FORS_SIGNATURE_SIZE);
    unsigned char adrs[22], pk[N], replayed[N], tampered_pk[N];

    memcpy(adrs, base, 22);
    FORS::fors_sign(sk_seed, digest, hash_ctx, adrs, sig.data());

    memcpy(adrs, base, 22);
    FORS::fors_pk_from_sig(sig.data(), digest, hash_ctx, adrs, pk);

    memcpy(adrs, base, 22);
    FORS::fors_pk_from_sig(sig.data(), digest, hash_ctx, adrs, replayed);
    EXPECT_EQ(0, memcmp(pk, replayed, N));

    std::vector<unsigned char> broken = sig;
    broken[FORS_SIGNATURE_SIZE / 2] ^= 0x01;

    memcpy(adrs, base, 22);
    FORS::fors_pk_from_sig(broken.data(), digest, hash_ctx, adrs, tampered_pk);
    EXPECT_NE(0, memcmp(pk, tampered_pk, N));
}

TEST(HypertreeTest, VerifiesAgainstStatelessRoot) {
    std::vector<unsigned char> seed = test_seed(0x66);
    const unsigned char* sk_seed = seed.data();
    const unsigned char* pk_seed = seed.data() + 2 * N;

    CSHA256 hash_ctx = midstate(pk_seed);

    unsigned char sl_root[N];
    unsigned char root_adrs[22] = {0};
    setLayerAddress(root_adrs, SPHX_LAYER_COUNT - 1);
    XMSS::xmss_node(sk_seed, hash_ctx, root_adrs, 0, SPHX_XMSS_HEIGHT, sl_root);

    unsigned char message[N];
    memset(message, 0x18, N);

    const uint64_t tree_index = 0x1234567;
    const uint32_t leaf_index = 11;

    std::vector<unsigned char> sig(HYPERTREE_SIGNATURE_SIZE);
    HT::hypertree_sign(message, sk_seed, hash_ctx, tree_index, leaf_index, sig.data());

    EXPECT_TRUE(HT::hypertree_verify(sig.data(), message, hash_ctx, tree_index, leaf_index, sl_root));

    sig[HYPERTREE_SIGNATURE_SIZE - 1] ^= 0x01;
    EXPECT_FALSE(HT::hypertree_verify(sig.data(), message, hash_ctx, tree_index, leaf_index, sl_root));
}

// Mirrors impl/test.py: every stateful counter of a BXMSS tree of depth 4.
TEST(SHRINCSTest, StatefulBalancedSignVerify) {
    const SecretKey& sk = balanced_key();
    std::vector<unsigned char> message = {'f', 'o', 'o', 'b', 'a', 'r', '!'};

    for (uint32_t state_ctr = 0; state_ctr < (1u << 4); state_ctr++)
    {
        std::vector<unsigned char> signature;
        ASSERT_TRUE(shrincs_sign(message, sk, state_ctr, {}, signature)) << "state_ctr " << state_ctr;

        // A BXMSS tree signs from a fixed depth, so every signature is the same size.
        EXPECT_EQ(stateful_sig_size(FXMSS_HEIGHT - 4), signature.size());
        EXPECT_TRUE(shrincs_verify(message, signature, sk.pk)) << "state_ctr " << state_ctr;
    }
}

// Mirrors impl/test.py: every stateful counter of a UXMSS tree of depth 16.
TEST(SHRINCSTest, StatefulUnbalancedSignVerify) {
    const SecretKey& sk = unbalanced_key();
    std::vector<unsigned char> message = {'f', 'o', 'o', 'b', 'a', 'r', '!'};

    for (uint32_t state_ctr = 0; state_ctr <= 16; state_ctr++)
    {
        uint64_t leaf_index;
        uint8_t leaf_height;
        ASSERT_TRUE(shrincs_sf_leaf_select(sk.structure, state_ctr, &leaf_index, &leaf_height));

        std::vector<unsigned char> signature;
        ASSERT_TRUE(shrincs_sign(message, sk, state_ctr, {}, signature)) << "state_ctr " << state_ctr;

        // A UXMSS tree signs deeper as the counter advances, growing the auth path.
        EXPECT_EQ(stateful_sig_size(leaf_height), signature.size());
        EXPECT_TRUE(shrincs_verify(message, signature, sk.pk)) << "state_ctr " << state_ctr;
    }
}

TEST(SHRINCSTest, LeafSelectMatchesSpec) {
    uint64_t leaf_index;
    uint8_t leaf_height;

    // UXMSS: the last counter lands on the left child of the root, the rest on index 1.
    for (uint32_t state_ctr = 0; state_ctr < 16; state_ctr++)
    {
        ASSERT_TRUE(shrincs_sf_leaf_select(STRUCTURE_UNBALANCED, state_ctr, &leaf_index, &leaf_height));
        EXPECT_EQ(1u, leaf_index);
        EXPECT_EQ(FXMSS_HEIGHT - 1 - state_ctr, leaf_height);
    }

    ASSERT_TRUE(shrincs_sf_leaf_select(STRUCTURE_UNBALANCED, 16, &leaf_index, &leaf_height));
    EXPECT_EQ(0u, leaf_index);
    EXPECT_EQ(FXMSS_HEIGHT - 16, leaf_height);

    EXPECT_FALSE(shrincs_sf_leaf_select(STRUCTURE_UNBALANCED, 17, &leaf_index, &leaf_height));

    // BXMSS: the counter is the leaf index, at a fixed depth.
    ASSERT_TRUE(shrincs_sf_leaf_select(STRUCTURE_BALANCED, 15, &leaf_index, &leaf_height));
    EXPECT_EQ(15u, leaf_index);
    EXPECT_EQ(FXMSS_HEIGHT - 4, leaf_height);

    EXPECT_FALSE(shrincs_sf_leaf_select(STRUCTURE_BALANCED, 16, &leaf_index, &leaf_height));

    // A depth-zero tree has no stateful leaves at all.
    EXPECT_FALSE(shrincs_sf_leaf_select({FXMSS_SHAPE_BALANCED, 0}, 0, &leaf_index, &leaf_height));
    EXPECT_FALSE(shrincs_sf_leaf_select({0x7f, 4}, 0, &leaf_index, &leaf_height));
}

// Mirrors impl/test.py: an exhausted counter falls back to the stateless path.
TEST(SHRINCSTest, StatelessFallbackSignVerify) {
    const SecretKey& sk = unbalanced_key();
    std::vector<unsigned char> message = {'f', 'o', 'o', 'b', 'a', 'r', '!'};

    std::vector<unsigned char> signature;
    ASSERT_TRUE(shrincs_sign(message, sk, 17, {}, signature));

    EXPECT_EQ(SPHX_SIGNATURE_SIZE, signature.size());
    EXPECT_TRUE(shrincs_verify(message, signature, sk.pk));
}

TEST(SHRINCSTest, StatelessHedgedVariantVerifies) {
    const SecretKey& sk = unbalanced_key();
    std::vector<unsigned char> message = {'h', 'e', 'd', 'g', 'e', 'd'};
    std::vector<unsigned char> opt_rand(N, 0xbe);

    std::vector<unsigned char> deterministic, hedged;
    ASSERT_TRUE(shrincs_sign(message, sk, 17, {}, deterministic));
    ASSERT_TRUE(shrincs_sign(message, sk, 17, opt_rand, hedged));

    EXPECT_NE(deterministic, hedged);
    EXPECT_TRUE(shrincs_verify(message, deterministic, sk.pk));
    EXPECT_TRUE(shrincs_verify(message, hedged, sk.pk));
}

TEST(SHRINCSTest, StatefulSigningIsDeterministic) {
    const SecretKey& sk = balanced_key();
    std::vector<unsigned char> message = {'d', 'e', 't'};

    std::vector<unsigned char> first, second;
    ASSERT_TRUE(shrincs_sign(message, sk, 3, {}, first));
    ASSERT_TRUE(shrincs_sign(message, sk, 3, {}, second));

    EXPECT_EQ(first, second);
}

TEST(SHRINCSTest, RejectsWrongMessage) {
    const SecretKey& sk = balanced_key();
    std::vector<unsigned char> message = {'o', 'r', 'i', 'g'};

    std::vector<unsigned char> signature;
    ASSERT_TRUE(shrincs_sign(message, sk, 0, {}, signature));

    std::vector<unsigned char> other = {'o', 'r', 'i', 'h'};
    EXPECT_FALSE(shrincs_verify(other, signature, sk.pk));
    EXPECT_FALSE(shrincs_verify({}, signature, sk.pk));
}

TEST(SHRINCSTest, RejectsWrongLeafIndex) {
    const SecretKey& sk = balanced_key();
    std::vector<unsigned char> message = {'l', 'e', 'a', 'f'};

    std::vector<unsigned char> signature;
    ASSERT_TRUE(shrincs_sign(message, sk, 2, {}, signature));

    // The leaf index is the 8 bytes that follow the randomizer.
    signature[N + 7] ^= 0x01;
    EXPECT_FALSE(shrincs_verify(message, signature, sk.pk));
}

TEST(SHRINCSTest, RejectsTamperedStatefulSignature) {
    const SecretKey& sk = balanced_key();
    std::vector<unsigned char> message = {'t', 'a', 'm', 'p', 'e', 'r'};

    std::vector<unsigned char> signature;
    ASSERT_TRUE(shrincs_sign(message, sk, 1, {}, signature));
    ASSERT_TRUE(shrincs_verify(message, signature, sk.pk));

    const size_t offsets[] = {
        0,                                    // randomizer
        N + 8,                                // WOTS+C grinding counter
        N + 8 + 2,                            // first WOTS+C chain
        signature.size() - 1                  // last auth path node
    };

    for (size_t offset : offsets)
    {
        std::vector<unsigned char> broken = signature;
        broken[offset] ^= 0x01;
        EXPECT_FALSE(shrincs_verify(message, broken, sk.pk)) << "offset " << offset;
    }
}

TEST(SHRINCSTest, RejectsMalformedStatefulSignature) {
    const SecretKey& sk = balanced_key();
    std::vector<unsigned char> message = {'s', 'i', 'z', 'e'};

    std::vector<unsigned char> signature;
    ASSERT_TRUE(shrincs_sign(message, sk, 0, {}, signature));

    EXPECT_FALSE(shrincs_verify(message, {}, sk.pk));
    EXPECT_FALSE(shrincs_verify(message, std::vector<unsigned char>(N + 8), sk.pk));

    // Truncating by one byte breaks the "2 more than a multiple of 16" rule.
    std::vector<unsigned char> short_sig(signature.begin(), signature.end() - 1);
    EXPECT_FALSE(shrincs_verify(message, short_sig, sk.pk));

    // Padding to a valid length still fails, because the auth path no longer matches.
    std::vector<unsigned char> long_sig = signature;
    long_sig.resize(signature.size() + N, 0);
    EXPECT_FALSE(shrincs_verify(message, long_sig, sk.pk));
}

TEST(SHRINCSTest, RejectsTamperedStatelessSignature) {
    const SecretKey& sk = unbalanced_key();
    std::vector<unsigned char> message = {'s', 'l'};

    std::vector<unsigned char> signature;
    ASSERT_TRUE(shrincs_sign(message, sk, 17, {}, signature));
    ASSERT_TRUE(shrincs_verify(message, signature, sk.pk));

    const size_t offsets[] = {
        0,                              // randomizer
        N,                              // FORS signature
        N + FORS_SIGNATURE_SIZE,        // hypertree signature
        SPHX_SIGNATURE_SIZE - 1
    };

    for (size_t offset : offsets)
    {
        std::vector<unsigned char> broken = signature;
        broken[offset] ^= 0x01;
        EXPECT_FALSE(shrincs_verify(message, broken, sk.pk)) << "offset " << offset;
    }
}

TEST(SHRINCSTest, RejectsForeignPublicKey) {
    const SecretKey& sk = balanced_key();
    std::vector<unsigned char> message = {'k', 'e', 'y'};

    std::vector<unsigned char> signature;
    ASSERT_TRUE(shrincs_sign(message, sk, 0, {}, signature));

    SecretKey other;
    std::vector<unsigned char> seed = test_seed(0x99);
    ASSERT_TRUE(shrincs_keygen(seed.data(), STRUCTURE_BALANCED, other));

    EXPECT_FALSE(shrincs_verify(message, signature, other.pk));
}

// Known-answer vectors generated with impl/shrincs.py from the SHRINCS BIP, using
// seed[i] = i * 7 + salt (mod 256) over 48 bytes and the message "foobar!".
TEST(SHRINCSTest, MatchesReferenceVectorsBalanced) {
    const SecretKey& sk = balanced_key();
    std::vector<unsigned char> message = {'f', 'o', 'o', 'b', 'a', 'r', '!'};

    EXPECT_EQ("e0e7eef5fc030a11181f262d343b4249", to_hex(sk.pk.seed.data(), N));
    EXPECT_EQ("176e4fe4edd3da85abd948648331f9da", to_hex(sk.pk.sl_root.data(), N));
    EXPECT_EQ("d9afd2ca0f3ccea8928397a3f7fae8a3", to_hex(sk.pk.sf_root.data(), N));

    struct Vector { uint32_t state_ctr; size_t size; const char* digest; };
    const Vector vectors[] = {
        {0, 602, "9a6792711aa775441eece0d9d265dfbcaff01b10f5c4922cb1d49b757d275b6f"},
        {1, 602, "c0cc8a83333225081ad9e6c14d895fc9cfb47ddc02ce25cdd33d1506b2aadad4"},
        {3, 602, "42faf4f165e1c01bc09277a14f5b862872ef52296aa5e2b7bf9d3e6f16892ce0"}
    };

    for (const Vector& vector : vectors)
    {
        std::vector<unsigned char> signature;
        ASSERT_TRUE(shrincs_sign(message, sk, vector.state_ctr, {}, signature));

        EXPECT_EQ(vector.size, signature.size()) << "state_ctr " << vector.state_ctr;
        EXPECT_EQ(vector.digest, sha256_hex(signature)) << "state_ctr " << vector.state_ctr;
    }
}

TEST(SHRINCSTest, MatchesReferenceVectorsUnbalanced) {
    const SecretKey& sk = unbalanced_key();
    std::vector<unsigned char> message = {'f', 'o', 'o', 'b', 'a', 'r', '!'};

    EXPECT_EQ("20272e353c434a51585f666d747b8289", to_hex(sk.pk.seed.data(), N));
    EXPECT_EQ("1f2903d4077bcd6d3fa0c11f9173d386", to_hex(sk.pk.sl_root.data(), N));
    EXPECT_EQ("5e64a7f6c36dd9a0a795944147c6ffa8", to_hex(sk.pk.sf_root.data(), N));

    struct Vector { uint32_t state_ctr; size_t size; const char* digest; };
    const Vector vectors[] = {
        {0,  554,  "1663888c5c9c07b8f92dfcf64bafb8e1f1418b678b5a5641b72edc833f3c868f"},
        {1,  570,  "9eb5994bc3936d9de8ab1141dfe48bc020b4322db1a66c7b4cef3c8da1cc67b8"},
        {3,  602,  "f41fd96ec17d40ccf760632a071e285c5e86e1f8532c8d77055fe87de998e232"},
        // An exhausted counter falls back to the stateless SLH-DSA path.
        {17, 5776, "ca48ea067f53410857c53ba17dc357387a9d31ba3a9e216de5e71776c53f454b"}
    };

    for (const Vector& vector : vectors)
    {
        std::vector<unsigned char> signature;
        ASSERT_TRUE(shrincs_sign(message, sk, vector.state_ctr, {}, signature));

        EXPECT_EQ(vector.size, signature.size()) << "state_ctr " << vector.state_ctr;
        EXPECT_EQ(vector.digest, sha256_hex(signature)) << "state_ctr " << vector.state_ctr;
    }
}

// A UXMSS tree of depth 255 drives the auth-path index past a 64-bit shift width,
// where shifting the leaf index by >= 64 bits would be undefined behaviour.
TEST(SHRINCSTest, MatchesReferenceVectorsFullDepth) {
    SecretKey sk;
    std::vector<unsigned char> seed(3 * N);
    for (size_t i = 0; i < seed.size(); i++)
    {
        seed[i] = static_cast<unsigned char>(i);
    }
    ASSERT_TRUE(shrincs_keygen(seed.data(), {FXMSS_SHAPE_UNBALANCED, 255}, sk));

    EXPECT_EQ("804387b0e31475f83d1eafd3ac2045b1", to_hex(sk.pk.sf_root.data(), N));

    std::vector<unsigned char> message(32, 0);

    struct Vector { uint32_t state_ctr; size_t size; const char* digest; };
    const Vector vectors[] = {
        {63,  1562, "cc327c6a3491ee7b730b74528fe2adca94b737a755f66b221857c82bab3439a5"},
        {64,  1578, "4499099c304f0f115fdb072bff6d4836bf6ec8079b964ed08f40c96acdcc4db8"},
        {65,  1594, "56371e629b52e0d4b9b719ea02913fffbfe280dc2b317aad3d93fb799ac4e2db"},
        {100, 2154, "2419d2aba64f9c19b0725fea0dc94d5563e060fd75ec8f27ff46c53d8e8eaba5"},
        {254, 4618, "1317a4867a535668effa38175e08121e217478ee760406d01a3c4c61c01f3382"},
        {255, 4618, "219f6dae88f703cc96dff57264c623c12c3e91a4bbda8e0e0b8375f322c99666"}
    };

    for (const Vector& vector : vectors)
    {
        std::vector<unsigned char> signature;
        ASSERT_TRUE(shrincs_sign(message, sk, vector.state_ctr, {}, signature)) << "state_ctr " << vector.state_ctr;

        EXPECT_EQ(vector.size, signature.size()) << "state_ctr " << vector.state_ctr;
        EXPECT_EQ(vector.digest, sha256_hex(signature)) << "state_ctr " << vector.state_ctr;
        EXPECT_TRUE(shrincs_verify(message, signature, sk.pk)) << "state_ctr " << vector.state_ctr;
    }

    // The tree holds tree_depth + 1 leaves, so 256 exhausts it.
    uint64_t leaf_index;
    uint8_t leaf_height;
    EXPECT_TRUE(shrincs_sf_leaf_select(sk.structure, 255, &leaf_index, &leaf_height));
    EXPECT_FALSE(shrincs_sf_leaf_select(sk.structure, 256, &leaf_index, &leaf_height));
}

TEST(SHRINCSTest, StructuresProduceDistinctStatefulRoots) {
    EXPECT_NE(balanced_key().pk.sf_root, unbalanced_key().pk.sf_root);

    // Both keys are derived from different seeds, so the stateless roots differ too.
    EXPECT_NE(balanced_key().pk.sl_root, unbalanced_key().pk.sl_root);
}

namespace {

// A cached signature must be indistinguishable from a recomputed one.
void expect_cache_matches_plain(const std::vector<unsigned char>& structure, unsigned char salt, uint32_t last_ctr)
{
    std::vector<unsigned char> seed = test_seed(salt);
    std::vector<unsigned char> message(32, 0x5e);

    SecretKey plain, cached;
    std::vector<unsigned char> cache;
    ASSERT_TRUE(shrincs_keygen(seed.data(), structure, plain));
    ASSERT_TRUE(shrincs_keygen(seed.data(), structure, cached, &cache));

    EXPECT_EQ(plain.pk.sf_root, cached.pk.sf_root);
    EXPECT_EQ(cache.size(), FXMSS::fxmss_cache_size(structure.data()));
    EXPECT_GT(cache.size(), 0u);

    for (uint32_t ctr = 0; ctr <= last_ctr; ctr++)
    {
        std::vector<unsigned char> a, b;
        ASSERT_TRUE(shrincs_sign(message, plain, ctr, {}, a)) << "ctr " << ctr;
        ASSERT_TRUE(shrincs_sign(message, cached, ctr, {}, b, &cache)) << "ctr " << ctr;

        EXPECT_EQ(a, b) << "ctr " << ctr;
        EXPECT_TRUE(shrincs_verify(message, b, cached.pk)) << "ctr " << ctr;
    }
}

}

TEST(CacheTest, UnbalancedMatchesPlainPath) {
    expect_cache_matches_plain({FXMSS_SHAPE_UNBALANCED, 16}, 0x31, 16);
}

TEST(CacheTest, BalancedMatchesPlainPath) {
    expect_cache_matches_plain({FXMSS_SHAPE_BALANCED, 6}, 0x32, 63);
}

TEST(CacheTest, UnbalancedCacheHoldsEveryNode) {
    std::vector<unsigned char> structure = {FXMSS_SHAPE_UNBALANCED, 255};

    // Two nodes per depth, which is the whole caterpillar tree bar the root.
    EXPECT_EQ(2u * 255u * N, FXMSS::fxmss_cache_size(structure.data()));
}

TEST(CacheTest, BalancedCacheStaysSmall) {
    // A BDS state is O(depth), unlike the 2^depth nodes of the tree itself.
    for (unsigned char depth : {8, 12, 16})
    {
        std::vector<unsigned char> structure = {FXMSS_SHAPE_BALANCED, depth};
        EXPECT_LT(FXMSS::fxmss_cache_size(structure.data()), 4096u) << "depth " << (int)depth;
    }
}

TEST(CacheTest, BalancedRejectsNonSequentialCounters) {
    std::vector<unsigned char> seed = test_seed(0x33);
    std::vector<unsigned char> structure = {FXMSS_SHAPE_BALANCED, 5};
    std::vector<unsigned char> message(32, 1), cache, sig;

    SecretKey sk;
    ASSERT_TRUE(shrincs_keygen(seed.data(), structure, sk, &cache));

    // The BDS state tracks one leaf, so skipping or replaying must be refused.
    EXPECT_FALSE(shrincs_sign(message, sk, 4, {}, sig, &cache));
    EXPECT_TRUE(shrincs_sign(message, sk, 0, {}, sig, &cache));
    EXPECT_FALSE(shrincs_sign(message, sk, 0, {}, sig, &cache));
    EXPECT_TRUE(shrincs_sign(message, sk, 1, {}, sig, &cache));
}

TEST(CacheTest, UnbalancedAcceptsAnyCounterOrder) {
    std::vector<unsigned char> seed = test_seed(0x34);
    std::vector<unsigned char> structure = {FXMSS_SHAPE_UNBALANCED, 8};
    std::vector<unsigned char> message(32, 2), cache;

    SecretKey sk;
    ASSERT_TRUE(shrincs_keygen(seed.data(), structure, sk, &cache));

    // The unbalanced cache is read-only, so counters may be used out of order.
    for (uint32_t ctr : {5u, 0u, 8u, 3u, 5u})
    {
        std::vector<unsigned char> sig;
        ASSERT_TRUE(shrincs_sign(message, sk, ctr, {}, sig, &cache)) << "ctr " << ctr;
        EXPECT_TRUE(shrincs_verify(message, sig, sk.pk)) << "ctr " << ctr;
    }
}

TEST(CacheTest, StatelessPathIgnoresCache) {
    std::vector<unsigned char> seed = test_seed(0x35);
    std::vector<unsigned char> structure = {FXMSS_SHAPE_UNBALANCED, 4};
    std::vector<unsigned char> message(32, 3), cache;

    SecretKey sk;
    ASSERT_TRUE(shrincs_keygen(seed.data(), structure, sk, &cache));

    std::vector<unsigned char> with_cache, without_cache;
    ASSERT_TRUE(shrincs_sign(message, sk, 99, {}, with_cache, &cache));
    ASSERT_TRUE(shrincs_sign(message, sk, 99, {}, without_cache));

    EXPECT_EQ(SPHX_SIGNATURE_SIZE, with_cache.size());
    EXPECT_EQ(without_cache, with_cache);
    EXPECT_TRUE(shrincs_verify(message, with_cache, sk.pk));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
