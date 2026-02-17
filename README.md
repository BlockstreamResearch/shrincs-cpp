# SHRINCS
C++ implementation of the SHRINCS post-quantum signature scheme.

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

### Build Library
Compiles the static library `libshrincs.a`
```bash
make build
```

### Run Unit Tests
Runs the GoogleTest suite:
```bash
make test
```

### Run Benchmark
Measures signature and verification speed:
```bash
make benchmark
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