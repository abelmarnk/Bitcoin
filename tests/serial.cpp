#include "../src/Serial/Serial.h"
#include "../src/Compute/Compute.h"
#include <catch/catch_amalgamated.hpp>

TEST_CASE("Serialization", "[endian]") {
    auto value_1 = GENERATE(
        25555555, 
        1, 
        12345678);
    BigNum bignum_value(value_1);
    
    std::vector<uint8_t> bignum_value_big_bytes = bignum_value.to_std_vec_32();
    std::vector<uint8_t> bignum_value_little_bytes = bignum_value_big_bytes;
    std::reverse(bignum_value_little_bytes.begin(), bignum_value_little_bytes.end());

    uint32_t value_2 = bignum_value.get_unsigned_small();
    REQUIRE(value_2 == value_1);

    uint32_t value_3;
    std::memcpy(&value_3, bignum_value_little_bytes.data(), sizeof(value_3));
    REQUIRE(value_3 == value_1);
}
