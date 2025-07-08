#include "../src/Script/Script.h"
#include <catch/catch_amalgamated.hpp>


TEST_CASE("Script test","[script][serialization][op_checksig]"){

    std::string private_key_hex = GENERATE(
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

    INFO("Testing key: " << private_key_hex);
    INFO("Testing message size: " << message.size());

    PrivateKey private_key(BigNum(private_key_hex), Secp256k1_Generator);
    BigPoint public_key = private_key.pubkey;

    auto signature = secp256k1_sign(private_key, message);
    
    std::deque<ScriptInput> inputs;
    
    auto signature_bytes = signature.der_to_std_vec();
    
    auto public_key_bytes = public_key.compressed_sec_to_std_vec();
    
    inputs.push_front(ScriptInput::OpCode::OP_CHECKSIG);
    inputs.push_front(public_key_bytes);
    inputs.push_front(signature_bytes);
    
    Script script(inputs);

    REQUIRE(script.evaluate(message));

    std::vector<uint8_t> serialization;

    script.serialize(serialization);

    Script script_2(serialization.begin());

    REQUIRE(script_2.evaluate(message));
}

TEST_CASE("Script test","[script][serialization][op_add][op_sub]") {

    ScriptInput input_1 = GENERATE(
        int_to_big_endian_bytes_no_pad(10),
        int_to_big_endian_bytes_no_pad(20),
        int_to_big_endian_bytes_no_pad(30),
        int_to_big_endian_bytes_no_pad(40)
    );

    ScriptInput input_2 = GENERATE(
        int_to_big_endian_bytes_no_pad(40),
        int_to_big_endian_bytes_no_pad(30),
        int_to_big_endian_bytes_no_pad(20),
        int_to_big_endian_bytes_no_pad(10)
    );

    ScriptInput input_3 = GENERATE(
        ScriptInput::OpCode::OP_SUB,
        ScriptInput::OpCode::OP_ADD
    );

    std::deque<ScriptInput> inputs;

    inputs.push_front(input_3);
    inputs.push_front(input_1);
    inputs.push_front(input_2);

    Script script_1(inputs);

    REQUIRE(script_1.evaluate());

    std::vector<uint8_t> result;
    
    script_1.serialize(result);

    Script script_2(result.cbegin());

    REQUIRE(script_2.evaluate());
}
