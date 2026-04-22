# Bitcoin Project

This is a modular Bitcoin protocol implementation exploring transaction validation, scripting, and networking.
## Current State

The project currently does the following:

- Parses, serializes, and reserializes Bitcoin transactions.
- Implements transaction validation for the examples covered by the book.
- Evaluates common Bitcoin Script patterns, including P2PKH, P2SH, P2WPKH, and P2WSH.
- Computes hashes, digests, Merkle roots, and Merkle proofs.
- Implements Bloom filters for BIP37-style SPV use cases.
- Handles block parsing and proof-of-work checks.
- Includes basic network interaction for transaction lookups and peer handshake tests.
- Ships with a Catch2-based test suite that covers the book-driven examples.

## What It Does Not Do

This project does not try to be a full Bitcoin implementation. In particular, it does not:

- Maintain a UTXO set or mempool.
- Relay blocks or transactions as a full P2P node.
- Perform peer discovery or maintain long-lived network state.
- Provide wallet features, address management, or key storage.
- Expose a GUI or RPC server.
- Aim for full consensus coverage.

## Requirements

- CMake 3.28 or newer
- A C++23 compiler (g++ 13 or clang++ 17 or newer)
- Boost (headers + `system`, `filesystem`, `thread`, `chrono`, `asio`, `beast`)
- OpenSSL
- Catch2 3
- nlohmann_json

On Ubuntu / Debian:

```bash
sudo apt-get install -y \
    cmake build-essential \
    libboost-all-dev \
    libssl-dev \
    nlohmann-json3-dev \
    catch2
```

## Build

From the repository root:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

The Debug build is configured with AddressSanitizer, so it is the best mode for development and test runs.

## Run the Tests

The test binary is created at `build/BitcoinCpp_Tests`.

### List available tests

```bash
./build/BitcoinCpp_Tests --list-tests
```

### Run the offline suite

This excludes the network-dependent tests and is the quickest way to verify the project:

```bash
./build/BitcoinCpp_Tests "~[network]" --reporter compact
```

### Run only the network tests

```bash
./build/BitcoinCpp_Tests "[network]" --reporter compact
```

### Run the full suite

```bash
./build/BitcoinCpp_Tests --reporter compact
```
