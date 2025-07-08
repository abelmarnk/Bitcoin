#include "../src/Block/Block.h"
#include <catch/catch_amalgamated.hpp>

TEST_CASE("Block", "[block][serialization][parsing][proof-of-work]") {
    std::string block_hex = GENERATE(
        "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1\
cd00200000000006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb\
5a4ac4247e9f337221b4d4c86041b0f2b5710"
    );

    std::vector<uint8_t> block_serialization_1 = hex_to_std_vec(block_hex);
    Block block(block_serialization_1.cbegin());

    std::vector<uint8_t> block_serialization_2;
    block.serialize(block_serialization_2);

    REQUIRE(block_serialization_2 == block_serialization_1);
    REQUIRE(block.check_pow());

    auto difficulty = block.difficulty(block.bits);
    REQUIRE(difficulty > 0);

    auto target = block.bits_to_target(block.bits);
    auto bits_from_target = block.target_to_bits(target);
    REQUIRE(bits_from_target == block.bits);
}


TEST_CASE("Block", "[block][target][bip-support]") {
    std::vector<uint8_t> first = GENERATE(hex_to_std_vec(
        "000000203471101bbda3fe307664b3283a9ef0e97d9a38a7eacd88000000000000\
00000010c8aba8479bbaa5e0848152fd3c2289ca50e1c3e58c9a4faaafbdf5803c5448ddb8455\
97e8b0118e43a81d3"
    ));
    std::vector<uint8_t> last = GENERATE(hex_to_std_vec(
        "02000020f1472d9db4b563c35f97c428ac903f23b7fc055d1cfc260\
00000000000000000b3f449fcbe1bc4cfbcb8283a0d2c037f961a3fdf2b8bedc14\
4973735eea707e1264258597e8b0118e5f00474"
    ));
    std::vector<uint8_t> next = GENERATE(hex_to_std_vec(
        "0200002099d6a70c547bbaa1a820490bd02cc378d3bc6e2046943\
8010000000000000000b66a0b024cfdf07d0dd97e18ad6ef1a411b0452129d3b\
fe3e6ebae55defec4dd95425859308d0118bc260a08"
    ));

    std::array<bool, 3> bip_flags = GENERATE(
        std::array<bool, 3>{true, false, true}
    );

    Block first_block(first.begin());
    Block last_block(last.begin());
    Block next_block(next.begin());

    auto calculated_target = Block::calculate_new_target(first_block, last_block);
    auto calculated_bits = Block::target_to_bits(calculated_target);

    REQUIRE(calculated_bits == next_block.bits);
    REQUIRE(last_block.bip_141() == bip_flags[0]);
    REQUIRE(last_block.bip_91() == bip_flags[1]);
    REQUIRE(last_block.bip_9() == bip_flags[2]);
}
