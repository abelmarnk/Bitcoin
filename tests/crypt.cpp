#include "../src/Crypt/Crypt.h"
#include "../src/Compute/Compute.h"
#include <catch/catch_amalgamated.hpp>


TEST_CASE("ECDSA test", "[crypto]") {

    std::string key_hex = GENERATE(
        "99f2882e",
        "12345678",
        "ea",
        "433423234aea"
    );

    std::vector<uint8_t> message = GENERATE(
        std::vector<uint8_t>{1,2,3,4,5,6,7,8},
        std::vector<uint8_t>{9,8,7,6,5,4,3,2},
        std::vector<uint8_t>{0xff, 0xee, 0xdd},
        std::vector<uint8_t>{0, 1, 0, 1, 0, 1}
    );

    INFO("Testing key: " << key_hex);
    INFO("Testing message size: " << message.size());

    PrivateKey priv_key(BigNum(key_hex), Secp256k1_Generator);
    BigPoint pub_key_point = priv_key.pubkey;

    auto sig = secp256k1_sign(priv_key, message);

    REQUIRE(secp256k1_verify(sig, message, pub_key_point));

    auto pub_key_bytes = pub_key_point.uncompressed_sec_to_std_vec();
    BigPoint reconstructed(pub_key_point.a, pub_key_point.b);
    reconstructed.uncompressed_sec_from_std_vec(pub_key_bytes);

    REQUIRE(secp256k1_verify(sig, message, reconstructed));
}
