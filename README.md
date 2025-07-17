This project is a personal exploration of the internals of Bitcoin. It is not a full node or wallet, but attempts to implements Bitcoin concepts, like transaction parsing, serialization, validation, and basic network interaction.


What it does

Transaction Parsing and Serialization:
Parses and serializes Bitcoin transactions, providing insight into the structure and encoding of Bitcoin data.

Transaction Validation:
Implements basic transaction validation logic.

Note: This does not include checking whether transaction inputs have already been spent (no UTXO set or mempool).

Script Evaluation:
Includes a partial implementation of Bitcoin Script, supporting common script types such as P2PKH, P2SH, P2WPKH, and P2WSH.

The code draws heavily from Jimmy Song’s Programming Bitcoin and https://learnmeabitcoin.com/

What it doesn't do

No UTXO Set or Double-Spend Checking:
Does not track spent outputs or prevent double-spending.

Not a Full Node:
Does not relay blocks or transactions, manage peers, or maintain a blockchain.

Partial Script Engine:
Script evaluation is simplified and does not cover all edge cases or opcodes.

Consensus Rules:
Some transactions may be marked as valid even if they would be rejected by a full node. They are pointed out in the code.

No Full Network Support:
Only the handshake is implemented; no block or transaction relay, peer management, or full protocol support.

No Wallet Functionality:
Does not generate addresses, manage keys, or sign transactions.

No GUI or RPC:
Command-line only, no user interface or remote procedure call support.

Dependencies
C++23 or later

Boost (system, filesystem, thread, chrono)

OpenSSL

nlohmann_json

Catch2 (included as amalgamated header and compiled source)

All dependencies are managed with CMake.

Building
Clone the repository and ensure all dependencies are available on your system.

Edit the CMakeLists.txt file:

Update the paths for catch_amalgamated.cpp, nlohmann_json, and catch_2 to match your local setup.

Build with CMake:
Run Tests.

Possible additions

Implementing a UTXO set and double-spend checking.
Expanding the script engine to cover all standard opcodes and edge cases.
Adding full network support (block/transaction relay, peer discovery, etc).
Making validation logic fully conformant to Bitcoin consensus rules.
Adding more comprehensive tests.
