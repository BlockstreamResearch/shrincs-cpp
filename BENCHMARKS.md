# Benchmarks

Numbers produced by [tests/bench.cpp](./tests/bench.cpp). To reproduce:

```bash
make OPENMP=1 benchmark   # multi-threaded
make benchmark            # single-threaded
```

Every row is the mean and the best of its runs: 100 for operations in the millisecond range, 5000 for the microsecond ones. The best-of column is the more stable of the two, so the speedup column is derived from it.

## Test machine

| | |
|---|---|
| CPU | Apple M5 Max, 6 performance + 12 efficiency cores |
| Memory | 48 GB |
| OpenMP | libomp 22.1.8, 18 threads |
| SHA256 | `arm_shani(1way,2way)` — hardware SHA2 instructions |

The SHA256 backend is chosen at runtime by `SHA256AutoDetect()`. Without it the library falls back to the portable C implementation, which is several times slower, so the call has to happen once before any measurement.

## UNBALANCED tree, depth 255

Cache: **8160 bytes** full, **4096 bytes** leaves only.

| operation | 1 thread mean | 1 thread best | 18 threads mean | 18 threads best | speedup | signature |
|---|---:|---:|---:|---:|---:|---:|
| keygen | 11574.90 | 11177.38 | 1284.42 | 811.92 | 13.8× | — |
| keygen, full cache | 11291.94 | 11190.83 | 1211.58 | 805.96 | 13.9× | — |
| keygen, leaf cache | 11417.01 | 11227.83 | 1183.23 | 818.42 | 13.7× | — |
| sign state 0 | 3579.59 | 3497.21 | 439.83 | 291.79 | 12.0× | 554 |
| sign state 0, full cache | 8.44 | 8.04 | 7.94 | 7.42 | — | 554 |
| sign state 0, leaf cache | 15.49 | 14.75 | 14.80 | 14.08 | — | 554 |
| verify state 0 | 6.77 | 6.50 | 6.82 | 6.50 | — | — |
| sign state 255 | 3561.26 | 3482.67 | 3570.19 | 3494.88 | 1.0× | 4618 |
| sign state 255, full cache | 9.86 | 9.46 | 12.07 | 11.38 | — | 4618 |
| sign state 255, leaf cache | 9.86 | 9.42 | 12.04 | 11.33 | — | 4618 |
| verify state 255 | 13.77 | 13.29 | 13.77 | 13.25 | — | — |
| sign stateless | 45231.55 | 45008.46 | 4512.28 | 3614.79 | 12.5× | 5776 |
| verify stateless | 46.32 | 45.33 | 40.51 | 39.12 | — | — |

All times in µs.

## BALANCED tree, depth 10

Cache: **651 bytes** of BDS state. The leaves-only mode does not apply here.

| operation | 1 thread mean | 1 thread best | 18 threads mean | 18 threads best | speedup | signature |
|---|---:|---:|---:|---:|---:|---:|
| keygen | 21910.26 | 21725.58 | 2135.73 | 1503.71 | 14.5× | — |
| keygen, build cache | 21931.90 | 21761.25 | 2145.84 | 1491.67 | 14.6× | — |
| sign stateful | 14195.01 | 14009.54 | 1861.42 | 1639.88 | 8.5× | 698 |
| sign stateful, cached | 65.83 | 10.21 | 65.88 | 7.75 | — | 698 |
| verify stateful | 7.03 | 6.75 | 7.06 | 6.71 | — | — |

All times in µs.

## Reading the numbers

**The leaf cache trades a little time for half the memory.** It keeps only the WOTS+C public keys and rebuilds the one internal node a path may need, at one hash per level below it — most expensive at state 0, where that node sits at the very top (+7 µs), and free at the deepest leaf, whose path holds nothing but leaves.

**Cache mode does not affect keygen.** All three keygen rows agree within noise: building the root takes the same hashes either way, the leaf mode just does not store the intermediates.

**`sign stateful, cached` should be read by its mean.** The balanced cache advances BDS state on every call, and the 8 µs best is the one counter where that step is trivial.

**Uncached signing at state 255 does not parallelise.** Its path is 255 siblings that are all single leaves, and `fxmss_sign` walks them serially, so each call stays below the threshold that turns the parallel region on. The siblings could be parallelised across instead, but this path only runs without a cache, and with one the same signature costs 9 µs.
