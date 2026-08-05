# SHRINCS
C++ implementation of the [SHRINCS](https://github.com/SHRINCS/shrincs-bip) post-quantum signature scheme.

> *⚠️ This project is a work in progress and is provided as-is for research, learning, and experimentation. It is not production-ready and has not undergone a formal security audit, code review, or verification process. This library may be incorrect, incomplete, or insecure.*

## Requirements

SHA256 is vendored in [btc_sha](./btc_sha/), so the library itself has no external dependencies. GoogleTest is only needed to run the test suite, and libomp only to build with parallelism.

### Linux:
```bash
sudo apt update
sudo apt install libgtest-dev build-essential libomp-dev
```

### macOS:
```bash
brew install googletest libomp
```

## Building & Testing

```bash
make build     # Build libshrincs.a
make tests     # Run GTest suite
make benchmark # Run performance benchmarks
```

## Parallelism

Key generation and stateless signing spend nearly all their time generating WOTS leaves, which are independent of each other. Adding `OPENMP=1` runs them across all cores:

```bash
make OPENMP=1 build
make OPENMP=1 benchmark
```

Without the flag the OpenMP pragmas are ignored, libomp is not needed, and the library builds exactly as it otherwise would. Signatures are byte-identical either way.

Verification and cached stateful signing are already fast enough that threads would only add overhead, so they are left alone. Thread count follows `OMP_NUM_THREADS`, and `make benchmark` reports what either build actually achieves on your machine. See [BENCHMARKS.md](./BENCHMARKS.md) for measurements from one.

## Signing cache

`shrincs_keygen` optionally fills a cache that `shrincs_sign` reuses, which avoids recomputing tree nodes on every signature:

```cpp
std::vector<unsigned char> cache;
shrincs_keygen(seed, structure, sk, &cache);
shrincs_sign(message, sk, state_ctr, opt_rand, signature, &cache);
```

Building it is free, since the nodes are filled during the traversal keygen performs anyway, and it turns stateful signing from a full tree walk into a handful of lookups.

### Unbalanced trees

The cache holds the whole tree bar the root, which is the public key anyway: both the WOTS+C public keys and the internal nodes above them, because an authentication path contains both. Being read-only, it may be used with counters in any order.

Passing `leaves_only` keeps only the WOTS+C public keys, halving the cache. An authentication path needs at most one internal node, and signing rebuilds it with one hash per level below it — far cheaper than regenerating the leaves that node covers. Worth it where memory is the scarce resource:

```cpp
shrincs_keygen(seed, structure, sk, &cache, true);
shrincs_sign(message, sk, state_ctr, opt_rand, signature, &cache, true);
```

The flag must match in both calls. `shrincs_sign` checks the cache against the size the mode implies and refuses a mismatch, so the two cannot silently disagree.

### Balanced trees

Storing every node is not an option, so the cache holds a BDS state instead, and `leaves_only` is ignored. That state only moves forwards, so counters must be used in sequence; signing rejects a counter the cache is not positioned on.

## Usage
To integrate SHRINCS into your project, include the headers and library (copy [include](./include/) directory and compiled `libshrincs.a` to your project):

### Example
See example [here](./tests/bench.cpp)

### Compilation command:
```bash
g++ main.cpp -I./include -L. -lshrincs -o my_app
```

Add `-lomp` when linking against a library built with `OPENMP=1`.

> [!IMPORTANT]
> Call `SHA256AutoDetect()` once at startup. Without it the vendored SHA256 never selects the hardware-accelerated implementation, and everything runs substantially slower.

Then run:
```bash
./my_app
```
