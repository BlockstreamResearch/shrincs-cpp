#include <cstdio>
#include <chrono>
#include <string>
#include <vector>
#include "shrincs.h"

#ifdef _OPENMP
#include <omp.h>
#endif

using namespace std;
using namespace SHRINCS;

static const int RUNS_SLOW = 100;
static const int RUNS_FAST = 5000;

// Just leave it here, in case we want to print signatures in hex for debugging
void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
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

template <typename F>
static void bench(const char* label, int reps, size_t sig_size, F fn)
{
    double total = 0, best = 1e18;

    for (int i = 0; i < reps; i++)
    {
        auto start = std::chrono::high_resolution_clock::now();
        fn();
        double elapsed = std::chrono::duration<double, std::micro>(
            std::chrono::high_resolution_clock::now() - start).count();

        total += elapsed;
        if (elapsed < best) best = elapsed;
    }

    printf("  %-30s %12.2f %12.2f %7d", label, total / reps, best, reps);
    if (sig_size) printf("  %8zu\n", sig_size);
    else          printf("  %8s\n", "-");
}

static void header(const char* title, const char* note)
{
    printf("\n%s\n", title);
    if (note) printf("%s\n", note);
    printf("  %-30s %12s %12s %7s  %8s\n", "operation", "mean, us", "min, us", "runs", "bytes");
}

int main()
{
    printf("SHA256:      %s\n", SHA256AutoDetect().c_str());
#ifdef _OPENMP
    printf("Parallelism: OpenMP, %d threads\n", omp_get_max_threads());
#else
    printf("Parallelism: disabled (build with OPENMP=1)\n");
#endif

    unsigned char seed[48];
    generate_random_bytes(seed, 48);

    vector<unsigned char> message(32, 0);
    vector<unsigned char> signature, opt_rand, cache, leaf_cache;
    // hexStringToBytes("8a276ceb95d10ed7705c9e25c9987cb4b1eaf73bcae7f922058c4e46e906a778", message.data());

    vector<unsigned char> structure = {FXMSS_SHAPE_UNBALANCED, 255};
    SecretKey sk;

    char note[128];
    snprintf(note, sizeof(note), "cache: %llu bytes full, %llu bytes leaves only",
             (unsigned long long)FXMSS::fxmss_cache_size(structure.data(), false),
             (unsigned long long)FXMSS::fxmss_cache_size(structure.data(), true));

    header("UNBALANCED tree, depth 255", note);
    bench("keygen", RUNS_SLOW, 0, [&] { SecretKey k; shrincs_keygen(seed, structure, k); });
    bench("keygen, full cache", RUNS_SLOW, 0, [&] { SecretKey k; vector<unsigned char> c; shrincs_keygen(seed, structure, k, &c); });
    bench("keygen, leaf cache", RUNS_SLOW, 0, [&] { SecretKey k; vector<unsigned char> c; shrincs_keygen(seed, structure, k, &c, true); });

    shrincs_keygen(seed, structure, sk, &cache);
    shrincs_keygen(seed, structure, sk, &leaf_cache, true);

    shrincs_sign(message, sk, 0, opt_rand, signature, &cache);
    bench("sign   state 0", RUNS_SLOW, signature.size(), [&] { shrincs_sign(message, sk, 0, opt_rand, signature); });
    bench("sign   state 0, full cache", RUNS_FAST, signature.size(), [&] { shrincs_sign(message, sk, 0, opt_rand, signature, &cache); });
    bench("sign   state 0, leaf cache", RUNS_FAST, signature.size(), [&] { shrincs_sign(message, sk, 0, opt_rand, signature, &leaf_cache, true); });
    bench("verify state 0", RUNS_FAST, 0, [&] { shrincs_verify(message, signature, sk.pk); });

    shrincs_sign(message, sk, 255, opt_rand, signature, &cache);
    bench("sign   state 255", RUNS_SLOW, signature.size(), [&] { shrincs_sign(message, sk, 255, opt_rand, signature); });
    bench("sign   state 255, full cache", RUNS_FAST, signature.size(), [&] { shrincs_sign(message, sk, 255, opt_rand, signature, &cache); });
    bench("sign   state 255, leaf cache", RUNS_FAST, signature.size(), [&] { shrincs_sign(message, sk, 255, opt_rand, signature, &leaf_cache, true); });
    bench("verify state 255", RUNS_FAST, 0, [&] { shrincs_verify(message, signature, sk.pk); });

    shrincs_sign(message, sk, 256, opt_rand, signature);
    bench("sign   stateless", RUNS_SLOW, signature.size(), [&] { shrincs_sign(message, sk, 256, opt_rand, signature); });
    bench("verify stateless", RUNS_FAST, 0, [&] { shrincs_verify(message, signature, sk.pk); });

    structure[0] = FXMSS_SHAPE_BALANCED;
    structure[1] = 10;

    snprintf(note, sizeof(note), "cache: %llu bytes BDS state (leaves only does not apply)",
             (unsigned long long)FXMSS::fxmss_cache_size(structure.data(), false));

    header("BALANCED tree, depth 10", note);
    bench("keygen", RUNS_SLOW, 0, [&] { SecretKey k; shrincs_keygen(seed, structure, k); });
    bench("keygen, build cache", RUNS_SLOW, 0, [&] { SecretKey k; vector<unsigned char> c; shrincs_keygen(seed, structure, k, &c); });
    shrincs_keygen(seed, structure, sk, &cache);

    uint32_t state_ctr = 0;
    shrincs_sign(message, sk, state_ctr++, opt_rand, signature, &cache);

    int bds_runs = (1 << structure[1]) - 1;
    if (bds_runs > RUNS_FAST) bds_runs = RUNS_FAST;

    bench("sign   stateful", RUNS_SLOW, signature.size(), [&] { shrincs_sign(message, sk, 0, opt_rand, signature); });
    bench("sign   stateful, cached", bds_runs, signature.size(), [&] { shrincs_sign(message, sk, state_ctr++, opt_rand, signature, &cache); });
    bench("verify stateful", RUNS_FAST, 0, [&] { shrincs_verify(message, signature, sk.pk); });

    printf("\n");

    return 0;
}
