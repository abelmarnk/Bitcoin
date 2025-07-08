#include "../src/Transaction/Transaction.h"
#include <catch/catch_amalgamated.hpp>


TEST_CASE("Transaction", "[transaction][fetch]"){
    try {
        std::string str = "4bf299cd765f4d616ec333b1efcae5fa61bc17f83ca0bbd715c6c60827e5cd76";

        for(uint8_t counter = 0; counter < str.size()/2; counter += 2){
            std::swap(str[counter], str[(str.size() - 1)- (1 + counter)]);
            std::swap(str[counter + 1], str[(str.size() - 1)- (counter)]);
	    }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

TEST_CASE("Transaction", "[transaction][parsing][serialization]") {

    auto tx_id = GENERATE(hex_to_std_array<32>(
        "f7b14b7f9bb5b61c7c4d8abb31241aa8d787e043f795bbdcea964bd30fb3b8e5"
    ));
    
    auto tx_index = GENERATE(0);
    auto locktime = GENERATE(0);
    auto version = GENERATE(1);
    bool testnet = GENERATE(true);

    std::vector<uint8_t> script_bytes = GENERATE(hex_to_std_vec(
        "76a914477c14873ce8778bf8f2f609ac4138ebc7c4f18488ac"
    ));

    Tx transaction_1;
    transaction_1.set_locktime(locktime);
    transaction_1.set_version(version);
    transaction_1.set_testnet(testnet);

    TxIn input;
    input.set_tx_id(tx_id);
    input.set_tx_index(tx_index);
    input.set_script(Script(script_bytes.cbegin(), script_bytes.size()));

    std::vector<uint8_t> serialization_1;

    input.serialize(serialization_1);

    TxIn parsed_input(serialization_1.begin());

    REQUIRE(parsed_input.get_tx_index() == tx_index);
    REQUIRE(parsed_input.get_sequence() == input.get_sequence());
    REQUIRE(parsed_input.get_tx_id() == tx_id);

    std::vector<uint8_t> serialization_2;
    parsed_input.get_script().serialize(serialization_2);

    REQUIRE(std::equal(serialization_2.begin() + 1, serialization_2.end(), // Skip over the varint for the script size.
    script_bytes.begin()));
}

TEST_CASE("Transaction", "[transaction][script][signature][public key][validation]") {
    auto tx_id = GENERATE(hex_to_std_array<32>(
        "f7b14b7f9bb5b61c7c4d8abb31241aa8d787e043f795bbdcea964bd30fb3b8e5"
    ));

    auto tx_index = GENERATE(0);
    auto locktime = GENERATE(0);
    auto version = GENERATE(1);
    bool testnet = GENERATE(true);

    std::vector<uint8_t> script_bytes = GENERATE(hex_to_std_vec(
        "76a914477c14873ce8778bf8f2f609ac4138ebc7c4f18488ac"
    ));

    Tx transaction_1;
    transaction_1.set_locktime(locktime);
    transaction_1.set_version(version);
    transaction_1.set_testnet(testnet);

    TxIn input;
    input.set_tx_id(tx_id);
    input.set_tx_index(tx_index);
    input.set_script(Script(script_bytes.cbegin(), script_bytes.size()));

    std::vector<uint8_t> serialization_1;
    input.serialize(serialization_1);

    std::string private_key_hex = GENERATE(
        "459804aba82fa30ba0491025918d84ca08757054cf1ddc596d24a95d9ed382d2"
    );

    PrivateKey key(BigNum(private_key_hex), Secp256k1_Generator);

    auto message_hash = get_sha_256(get_sha_256(serialization_1));
    BitcoinSignature signature = secp256k1_sign(key, BigNum(message_hash));

    std::vector<uint8_t> pubkey_bytes = key.pubkey.compressed_sec_to_std_vec();
    std::vector<uint8_t> signature_bytes = signature.der_to_std_vec();

    input.get_script().prepend(ScriptInput(pubkey_bytes));
    input.get_script().prepend(ScriptInput(signature_bytes));

    REQUIRE(input.get_script().evaluate(message_hash));
}

TEST_CASE("Transaction", "[transaction][p2pkh]") {
    auto tx_id = GENERATE(hex_to_std_array<32>(
        "07fb3985c040e3521a75347aa6ddc93de2ad4c48ead5ac071bf1d267422cb7c4"
    ));

    auto tx_index = GENERATE(0);
    auto locktime = GENERATE(0);
    auto version = GENERATE(1);
    bool testnet = GENERATE(true);
    
    auto script = GENERATE(
        create_p2pkh_out(decode_from_bitcoin_address("n3R9qYkfLW8EBJiRRTAc9GYrRUuxpFHiqo"))
    );
    
    Tx transaction_1;
    transaction_1.set_locktime(locktime);
    transaction_1.set_version(version);
    transaction_1.set_testnet(testnet);

    TxIn transaction_input;
    transaction_input.set_tx_id(tx_id);
    transaction_input.set_tx_index(tx_index);
    transaction_input.set_script_from_index_and_id(testnet);

    TxOut txout;
    txout.set_amount(5000);
    txout.set_script(script);

    transaction_1.set_in_txs({transaction_input});
    transaction_1.set_out_txs({txout});

    std::vector<uint8_t> serialization_1;
    transaction_1.serialize(serialization_1);
    serialization_1.insert(serialization_1.end(), Tx::SIGHASH_ALL.begin(), Tx::SIGHASH_ALL.end());

    std::string private_key_hex = GENERATE(
        "459804aba82fa30ba0491025918d84ca08757054cf1ddc596d24a95d9ed382d2"
    );

    PrivateKey private_key(BigNum(private_key_hex), Secp256k1_Generator);

    auto hash = DigestStream<HASH256_tag>::digest(serialization_1);
    auto signature = secp256k1_sign(private_key, BigNum(hash));

    std::deque<ScriptInput> inputs = {
        ScriptInput(signature.der_to_std_vec()),
        ScriptInput(private_key.pubkey.compressed_sec_to_std_vec())
    };

    transaction_input.set_script(Script(inputs));
    transaction_1.set_in_txs({transaction_input});

    REQUIRE(transaction_1.is_valid());

    std::vector<uint8_t> serialization_2;
    transaction_1.serialize(serialization_2);

    Tx transaction_2(serialization_2.begin());
    transaction_2.set_testnet(true);

    REQUIRE(transaction_2.is_valid());
}

TEST_CASE("Transaction", "[transaction][coinbase]") {
    std::vector<uint8_t> coinbase_tx = GENERATE(hex_to_std_vec(
        "01000000010000000000000000000000000000000000000000000000000000000000000000"
        "ffffffff1b03951a0604f15ccf5609013803062b9b5a0100072f425443432f200000000001"
        "ebc31495000000001976a9142c30a6aaac6d96687291475d7d52f4b469f665a688ac00000000"
    ));

    Tx transaction_1;
    transaction_1.parse(coinbase_tx.begin());

    REQUIRE(transaction_1.is_coinbase());
    auto height = transaction_1.extract_coinbase_block_height();
    REQUIRE(height.has_value());
    REQUIRE(height.value() > 0);

    std::vector<uint8_t> reserialized;
    transaction_1.serialize(reserialized);
    REQUIRE(reserialized == coinbase_tx);
}

TEST_CASE("Transaction", "[transaction][p2ms]") {
    std::string tx_hex = GENERATE(
        "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b4\
9aa43ad90ba26000000000490047304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac8\
94ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01fffff\
fff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000"
    );

    bool testnet = GENERATE(
        false
    );

    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(testnet);

    REQUIRE(tx.is_valid());
}

TEST_CASE("Transaction", "[transaction][p2sh]") {
    std::string tx_hex = GENERATE(
        "0100000003a5ee1a0fd80dfbc3142df136ab56e082b799c13aa977c048bdf8f61\
bd158652c000000006b48304502203b0160de302cded63589a88214fe499a25aa1d86a2ea09129945cd632476a12c0\
22100c77727daf0718307e184d55df620510cf96d4b5814ae3258519c0482c1ca82fa0121024f4102c1f1cf662bf99f2\
b034eb03edd4e6c96793cb9445ff519aab580649120ffffffff0fce901eb7b7551ba5f414735ff93b83a2a57403df11059\
ec88245fba2aaf1a0000000006a47304402204089adb8a1de1a9e22aa43b94d54f1e54dc9bea745d57df1a633e03dd9ede3c\
2022037d1e53e911ed7212186028f2e085f70524930e22eb6184af090ba4ab779a5b90121030644cb394bf381dbec91680bdf1\
be1986ad93cfb35603697353199fb285a119effffffff0fce901eb7b7551ba5f414735ff93b83a2a57403df11059ec88245fba2\
aaf1a0010000009300493046022100a07b2821f96658c938fa9c68950af0e69f3b2ce5f8258b3a6ad254d4bc73e11e022100e82f\
ab8df3f7e7a28e91b3609f91e8ebf663af3a4dc2fd2abd954301a5da67e701475121022afc20bf379bc96a2f4e9e63ffceb8652b2b\
6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052aeffffffff\
02a3b81b00000000001976a914ea00917f128f569cbdf79da5efcd9001671ab52c88ac80969800000000001976a9143dec0ead289be1af\
a8da127a7dbdd425a05e25f688ac00000000"
    );

    bool testnet = GENERATE(
        false
    );

    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(testnet);

    REQUIRE(tx.is_valid());
}

TEST_CASE("Transaction", "[transaction][p2wpkh]") {
    std::string tx_hex = GENERATE(
        "01000000000101ad2bb91208eef398def3ed3e784d9ee9b7befeb56a3053c35\
61849b88bc4cedf0000000000ffffffff037a3e0100000000001600148d7a0a3461e3891723e5fdf8129caa007\
5060cff7a3e0100000000001600148d7a0a3461e3891723e5fdf8129caa0075060cff0000000000000000256a234\
2697462616e6b20496e632e204a6170616e20737570706f727473205365675769742102483045022100a6e33a7aff\
720ba9f33a0a8346a16fdd022196862796d511d31978c40c9ad48b02206fb8f67bd699a8c952b3386a81d122c366d\
2d36cd08e2de21207e6aa6f96ce9501210283409659355b6d1cc3c32decd5d561abaac86c37a353b52895a5e6c196d6f44800000000" 
);

    bool testnet = GENERATE(
        false
    );

    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(testnet);

    REQUIRE(tx.is_valid());
}

TEST_CASE("Transaction", "[transaction][p2wsh][no-signature]") {
    std::string tx_hex = GENERATE(
        "020000000001018a39b5cdd48c7d45a31a89cd675a95f5de78aebeeda1e55ac35d7\
110c3bacfc60000000000ffffffff01204e0000000000001976a914ee63c8c790952de677d1f8019c9474d8409\
8d6e188ac0202123423aa20a23421f2ba909c885a3077bb6f8eb4312487797693bbcfe7e311f797e3c5b8fa8700000000"
    );

    bool testnet = GENERATE(false);

    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(testnet);

    REQUIRE(tx.is_valid());
}

TEST_CASE("Transaction", "[transaction][p2sh-2][p2pkh-2]") {
    std::string tx_hex = GENERATE(
        "0100000003a5ee1a0fd80dfbc3142df136ab56e082b799c13aa977c048bdf8f61\
bd158652c000000006b48304502203b0160de302cded63589a88214fe499a25aa1d86a2ea09129945cd632476a12c0\
22100c77727daf0718307e184d55df620510cf96d4b5814ae3258519c0482c1ca82fa0121024f4102c1f1cf662bf99f2\
b034eb03edd4e6c96793cb9445ff519aab580649120ffffffff0fce901eb7b7551ba5f414735ff93b83a2a57403df11059\
ec88245fba2aaf1a0000000006a47304402204089adb8a1de1a9e22aa43b94d54f1e54dc9bea745d57df1a633e03dd9ede3c\
2022037d1e53e911ed7212186028f2e085f70524930e22eb6184af090ba4ab779a5b90121030644cb394bf381dbec91680bdf1\
be1986ad93cfb35603697353199fb285a119effffffff0fce901eb7b7551ba5f414735ff93b83a2a57403df11059ec88245fba2\
aaf1a0010000009300493046022100a07b2821f96658c938fa9c68950af0e69f3b2ce5f8258b3a6ad254d4bc73e11e022100e82f\
ab8df3f7e7a28e91b3609f91e8ebf663af3a4dc2fd2abd954301a5da67e701475121022afc20bf379bc96a2f4e9e63ffceb8652b2b\
6a097f63fbee6ecec2a49a48010e2103a767c7221e9f15f870f1ad9311f5ab937d79fcaeee15bb2c722bca515581b4c052aeffffffff\
02a3b81b00000000001976a914ea00917f128f569cbdf79da5efcd9001671ab52c88ac80969800000000001976a9143dec0ead289be1af\
a8da127a7dbdd425a05e25f688ac00000000"
    );

    bool testnet = GENERATE(false);

    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(testnet);

    REQUIRE(tx.is_valid());
}


//This test fails.
TEST_CASE("Transaction", "[.][transaction][p2wsh-2]") {
    std::string tx_hex = GENERATE(
        "01000000000101390c5847e5740a9087637787f5a2d616e5976fc64f0e6defc9\
72a1cbc38098e50100000000ffffffff05b0d00800000000001976a9145306faffb8e5d09ea95c56f33bcd8d3e16\
f66ad688acf04902000000000017a914ac62546a0f25a826c785638ed8aad507adb9cdb38723b21400000000001976a\
914d134182663df3bab31881a5b50b1d0deb9aabeb388ac30e60200000000001976a914007303b4eb55d0bad9563dd2a3e\
cdce4b47a79a288ac745f620400000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c\
58d040047304402207b1a0229e1037ec53d3066bd1d73e9dd593df59711f3f0be129f3cb17ef79ecb02200d5561b8c3976c3d\
622ef83afaf410c0b93b3d68795a602e1aa504c3a68c482c0147304402203bee9c5b00e387101d8ac6c1adbca631046a29f28e2\
70e6dbdd3d22cad11216902201bd5632f64b07369e4ba010d1b6d9a4906930807823b1e283f5e2aa1f07541f8016952210375e00\
eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0\
e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"
    );

    bool testnet = GENERATE(false);

    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(testnet);

    REQUIRE(tx.is_valid());
}

TEST_CASE("Transaction", "[transaction][p2sh-p2wpkh]") {
    std::string tx_hex = GENERATE(
        "020000000001018fa608b5bc62dccfe8044016c4c78adc0e322048f3b0fbd0cc61b7aae0d7befe0\
000000017160014c5ef9be15ad56d39e269158b8de151fefc77d9c60100000001c4782c00000000001976a914674a8527a29f256135\
52267d0edfd181212becdc88ac024730440220079026ade4fba8cc896affedb992bc07251bc93fa310ae9d0e0bfd5340ecf8ee02205f\
4ce3ac1831ed41e20953c461a9f59922953a134362e7c8dd02237e541eec58012102e3592884734ce8431d31348cd16fef8ed943749d65\
1e8c6b27ae8c327db1a91600000000"
    );

    bool testnet = GENERATE(false);

    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(testnet);

    REQUIRE(tx.is_valid());
}

// This test also fails.
TEST_CASE("Transaction", "[.][transaction][p2sh-p2wsh]") {
    std::string tx_hex = GENERATE(
        "01000000000101b2ca63326ca2bd3f234600a947b69264c3f674242e2b\
c0480eccc7141460dccc03000000232200207399bb69ad56fa38b607ea8e1d9cd0039d9572f7a1da109e81\
38ed874a8dab36000000000318138e000000000017a91463726ec3b4193f16dcc046ee2ef223747ee6d7038\
7888a010000000000160014d092e604eabdf15a6dd8e806f5db0b6c25f9b94e8fd1750a0000000017a9140d67\
773a11679be5eafcf525140565525ccd768e870400483045022100fef90b907f4b3627f2483511f5fd00428af8b\
2a313390f0b33436d86982b31f7022037654763701372971e0fc441fdf15a94a72d77bd025e0d4793daedf2467cf3\
830147304402204d15c4de19e48e9b2890d89455d0817ab1d51916ae7957f513332b558a7afc00022022b361fce11c\
4417f240b7aa7d7c569be39f559a887e2ad9881e524a083c3544014752210287913ee7a28340bb536c7ff6ccfd3cf21\
12d9b7783083f459a554982eff84390210362a8997ef839a3282cb6c56a0803ec3da46fc2803742f5924839d42018104b2852ae00000000"
    );

    bool testnet = GENERATE(false);

    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(testnet);

    REQUIRE(tx.is_valid());
}
