# Verification Benchmarks: SHRINCS vs Schnorr

All benchmarks were performed on an **Intel Core i5-10300H @ 2.50GHz**. 

Schnorr benchmarks utilize the highly optimized [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1) library.

## Schnorr

| Signature Size | CPU cycles | Cycles per Byte (cpb) |
| -------------- | ---------- | --------------------- |
|    64 bytes    |   83 200   |        1 300          |

## SHRINCS_B
|   State   | Signature Size | CPU cycles | Cycles per Byte (cpb) |
| --------- | ---------------| ---------- | --------------------- |
|  q = 1    |   324 bytes    |  806 760   |         2 490         |
|  q = 10   |   468 bytes    |  819 000   |         1 750         |
|  q = 100  |   1 908 bytes  |  896 760   |          470          |
|  q = 142  |   2 564 bytes  |  923 040   |          360          |
| stateless |   2 568 bytes  | 1 753 944  |          683          |

## SHRINCS_L
|   State   | Signature Size | CPU cycles | Cycles per Byte (cpb) |
| --------- | ---------------| ---------- | --------------------- |
|  q = 1    |   1 092 bytes  |   33 852   |           31          |
|  q = 10   |   1 236 bytes  |   39 552   |           32          |
|  q = 100  |   2 676 bytes  |  107 040   |           40          |
|  q = 190  |   4 100 bytes  |  180 400   |           44          |
| stateless |   4 104 bytes  |  188 784   |           46          |