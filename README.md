# SHRINCS
C++ implementation of the [SHRINCS](https://github.com/BlockstreamResearch/HB-Liquid) post-quantum signature scheme.

## Requirements
Before building, run:

### Linux:
```bash
sudo apt update
sudo apt install libgtest-dev libssl-dev build-essential
```

### macOS:
```bash
brew install googletest openssl
```

## Building & Testing

```bash
make build     # Build libshrincs.a
make test      # Run GTest suite
make benchmark # Run performance benchmarks
```

## Usage
To integrate SHRINCS into your project, include the headers and library (copy [include](./include/) directory and compiled `libshrincs.a` to your project):

### Example
See example [here](./tests/bench.cpp)

### Compilation command:
```bash
g++ main.cpp -I./include -L. -lshrincs -lssl -lcrypto -o my_app
```

Then run:
```bash
./my_app
```