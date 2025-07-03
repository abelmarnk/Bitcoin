/*
#include <vector>
#include <variant>
#include <iomanip>
#include <iostream>
#include "../Transaction.h"
#include "../Debug functions.h"
#include "../Serial.h"
#include "../Block.h"




int tx_test() {

    std::string tx_hex =
        "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e0100\
00006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951\
c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0\
da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4\
038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a473044022078\
99531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b84\
61cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba\
1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c35\
6efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da\
6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c3\
4210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49\
abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd\
04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea833\
1ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c\
2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20df\
e7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948\
a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46\
430600";




    std::vector<uint8_t> bytes_1 = hex_to_std_vec(tx_hex);
    std::vector<uint8_t>::iterator bytes_iterator = bytes_1.begin();

    //TransactionOut MyTransactionOut = parseTransactionOut(bytes_iterator);

    auto bytes_const_iterator = bytes_1.cbegin();

    Tx tx(bytes_1.cbegin());

    std::vector<uint8_t> bytes_2;

    std::vector<uint8_t>::iterator bytes_2_iterator = bytes_2.begin();

    tx.serialize(bytes_2, bytes_2_iterator);

    std::cout << "Parsing starts here." << "\n" << "\n";

    if (BigNum(tx_hex) == BigNum(bytes_2))
        std::cout << "Equal" << "\n" << "\n";

    std::cout << tx_hex << std::endl << std::endl;

    HexDump(bytes_2.begin(), bytes_2.size());

    return 6;

}

int encoding_decoding_test_1() {
    std::vector<uint8_t> sec = hex_to_std_vec("029d386983fa7e28ceda99454d0258e89d5d8e07cdb155ac142ff6bae505997154");

    HexDump(sec.cbegin(), sec.size());

    std::string address_1 = encode_to_bitcoin_address(sec, true);

    std::cout << address_1;

    std::cout << "\n" << "\n";

    std::vector<uint8_t> hash = decode_from_bitcoin_address(address_1);

    HexDump(hash.cbegin(), hash.size());

    return 0;
}

int tx_in_test_1() {

    Tx test_transaction;
    test_transaction.set_locktime(0);
    test_transaction.set_version(1);
    test_transaction.set_testnet(true);

    TxIn input_transaction;
    input_transaction.set_tx_id(hex_to_std_array<32>("f7b14b7f9bb5b61c7c4d8abb31241aa8d787e043f795bbdcea964bd30fb3b8e5"));
    input_transaction.set_tx_index(0);

    std::vector<uint8_t> script_stream = hex_to_std_vec("76a914477c14873ce8778bf8f2f609ac4138ebc7c4f18488ac");

    std::vector<uint8_t>::iterator script_stream_iterator = script_stream.begin();

    HexDump(script_stream_iterator, script_stream.size());

    input_transaction.set_script(Script(script_stream.cbegin(), script_stream.size()));

    std::vector<uint8_t> input_serialization;
    std::vector<uint8_t>::iterator input_serialization_iterator = input_serialization.begin();

    input_transaction.serialize(input_serialization_iterator, input_serialization);

    input_serialization_iterator = input_serialization.begin();
    HexDump(input_serialization_iterator, input_serialization.size());

    TxIn new_transaction(input_serialization_iterator);

    std::cout << "\n" << "\n";
    std::cout << "Sequence: " << new_transaction.get_sequence();

    std::cout << "\n" << "\n";
    std::cout << "Index: " << new_transaction.get_tx_index();

    input_serialization.resize(0);

    auto temp = new_transaction.get_tx_id();

    std::cout << "ID: ";
    HexDump(temp.begin(), temp.size());

    input_serialization_iterator = input_serialization.begin();

    new_transaction.get_script().serialize(input_serialization, input_serialization_iterator);

    input_serialization_iterator = input_serialization.begin();

    std::cout << "Script: ";
    HexDump(input_serialization_iterator, input_serialization.size());

    return 0;
}

int tx_in_test_2() {

    Tx test_transaction;
    test_transaction.set_locktime(0);
    test_transaction.set_version(1);
    test_transaction.set_testnet(true);

    TxIn input_transaction;
    input_transaction.set_tx_id(hex_to_std_array<32>("f7b14b7f9bb5b61c7c4d8abb31241aa8d787e043f795bbdcea964bd30fb3b8e5"));
    input_transaction.set_tx_index(0);

    std::vector<uint8_t> script_stream = hex_to_std_vec("76a914477c14873ce8778bf8f2f609ac4138ebc7c4f18488ac");

    std::vector<uint8_t>::iterator script_stream_iterator = script_stream.begin();

    HexDump(script_stream_iterator, script_stream.size());

    input_transaction.set_script(Script(script_stream.cbegin(), script_stream.size()));

    std::vector<uint8_t> input_serialization;

    std::vector<uint8_t>::iterator input_serialization_iterator = input_serialization.begin();

    input_transaction.serialize(input_serialization_iterator, input_serialization);

    input_serialization_iterator = input_serialization.begin();

    HexDump(input_serialization_iterator, input_serialization.size());

    PrivateKey key(BigNum("459804aba82fa30ba0491025918d84ca08757054cf1ddc596d24a95d9ed382d2"), Secp256k1_Generator);

    BitcoinSignature new_signature = secp256k1_sign(key, BigNum(get_sha_256(get_sha_256(input_serialization))));

    decode_from_bitcoin_address("mn2vuv7mofHHeAVjYehNoVuibpkYALnrGU");

    std::vector<uint8_t> bytes_1 = key.pubkey.compressed_sec_to_std_vec();

    //bytes_1.back() = 12;

    std::vector<uint8_t> vector_signature = new_signature.der_to_std_vec();

    //std::cout << "Signature 1: ";

    //HexDump(VectorSignature.begin(), VectorSignature.size());

    //std::cout << "Public key hash 1 :";

    //HexDump(bytes_1.begin(), bytes_1.size());

    //input_transaction.set_script(Script(inputs));
    //std::cout << "Public key hash 2 :";

    //HexDump(get_hash_160(key.pubkey.compressed_sec_to_std_vec()).begin(), 20);

    input_transaction.get_script().prepend(ScriptInput(bytes_1));

    input_transaction.get_script().prepend(ScriptInput(vector_signature));

    std::cout << "Input count: " << input_transaction.get_script().get_input_count() << std::endl;

    //input_serialization.back() = 13;

    if (input_transaction.get_script().evaluate(get_sha_256(get_sha_256(input_serialization))))
        std::cout << "Well done!!!";

    return 0;
}

int test_y(){
    // A small test to check if get_unsigned_small is the same as to_std_vec_32
    // Also checks the endianess of my system(little-endian).

    uint32_t test_num_uint32_t = 25555555;
    std::cout << "TestNum(Original)(Dec): " << test_num_uint32_t << "\n" << "\n";

    std::cout << "TestNum(Original)(Hex): ";
    std::cout << std::hex << uint32_t(*reinterpret_cast<uint8_t*>(&test_num_uint32_t)) << " "
        << uint32_t(*(reinterpret_cast<uint8_t*>(&test_num_uint32_t) + 1)) << " "
        << uint32_t(*(reinterpret_cast<uint8_t*>(&test_num_uint32_t) + 2)) << " "
        << uint32_t(*(reinterpret_cast<uint8_t*>(&test_num_uint32_t) + 3)) << "\n" << "\n";


    BigNum test_num(25555555);

    // This should be displayed in reverse of the above, openssl stores numbers in big-endian.
    std::vector<uint8_t> test_vec = test_num.to_std_vec_32();
    std::cout << "TestNum(bytes_1)(Hex): ";

    HexDump(test_vec.begin(), test_vec.size());

    // This should be displayed in reverse of the above(little endian).
    std::reverse(test_vec.begin(), test_vec.end());
    std::cout << "TestNum(bytes_1 Reversed)(Hex): ";
    HexDump(test_vec.begin(), test_vec.size());


    uint32_t test_num_uint32 = test_num.get_unsigned_small();
    std::cout << "TestNum(UnsignedSmall)(Dec): " << std::dec << test_num_uint32 << "\n" << "\n";

    std::cout << "TestNum(UnsignedSmall)(Hex): ";
    std::cout << std::hex << uint32_t(*reinterpret_cast<uint8_t*>(&test_num_uint32)) << " "
        << uint32_t(*(reinterpret_cast<uint8_t*>(&test_num_uint32) + 1)) << " "
        << uint32_t(*(reinterpret_cast<uint8_t*>(&test_num_uint32) + 2)) << " "
        << uint32_t(*(reinterpret_cast<uint8_t*>(&test_num_uint32) + 3)) << "\n" << "\n";

        return 25;
}

int test_x() {

    std::cout << "Red and blue make purple." << std::endl;

    // Create and configure a transaction
    Tx test_transaction;
    test_transaction.set_locktime(0);
    test_transaction.set_version(1);
    test_transaction.set_testnet(true);

    // Configure the input transaction
    TxIn input_transaction;
    input_transaction.set_tx_id(hex_to_std_array<32>("07fb3985c040e3521a75347aa6ddc93de2ad4c48ead5ac071bf1d267422cb7c4"));
    input_transaction.set_tx_index(0);
    input_transaction.set_script_from_index_and_id(test_transaction.is_testnet()); // Fetch and set the script

    std::cout << "Script pub key: -"; 
    std::vector<uint8_t> serialization_script; 
    std::vector<uint8_t>::iterator serialization_script_iterator = serialization_script.begin();
    input_transaction.get_script().serialize(serialization_script, serialization_script_iterator);
    HexDump(serialization_script.begin(), serialization_script.size());


    // Configure the output transaction
    TxOut output_transaction;
    output_transaction.set_amount(5000);
    output_transaction.set_script(std::move(create_p2pkh_out(decode_from_bitcoin_address("n3R9qYkfLW8EBJiRRTAc9GYrRUuxpFHiqo"))));

    // Add inputs and outputs to the transaction
    test_transaction.set_in_txs(std::vector<TxIn>{input_transaction});
    test_transaction.set_out_txs(std::vector<TxOut>{output_transaction});

    // serialize the transaction for signing
    std::vector<uint8_t> input_serialization;
    std::vector<uint8_t>::iterator input_serialization_iterator = input_serialization.begin();
    test_transaction.serialize(input_serialization, input_serialization_iterator);
    input_serialization.insert(input_serialization.end(), Tx::SIGHASH_ALL.begin(), Tx::SIGHASH_ALL.end());

    // Generate a private key
    PrivateKey private_key_(BigNum("459804aba82fa30ba0491025918d84ca08757054cf1ddc596d24a95d9ed382d2"), Secp256k1_Generator);

    std::cout << "pre-serialized transaction: " << "\n";
    HexDump(input_serialization.begin(), input_serialization.size());    // Hash the serialized transaction

    std::vector<uint8_t> hash = get_hash_256(input_serialization);

    // Sign the transaction
    BitcoinSignature signature_ = secp256k1_sign(private_key_, BigNum(hash));
    std::vector<uint8_t> signature_serialization = signature_.der_to_std_vec();
    std::vector<uint8_t> public_key = private_key_.pubkey.compressed_sec_to_std_vec();

    // Log key, address and signature.
    std::cout << "Public key: " << private_key_.pubkey.compressed_sec_to_hex() << "\n";
    std::cout << "Address: " << encode_to_bitcoin_address(private_key_.pubkey.compressed_sec_to_std_vec(), true) << "\n";
    std::cout << "Signature: ";

    std::cout << "Primitive hash:- " << std::endl;
    HexDump(hash.begin(), hash.size());

    HexDump(signature_serialization.begin(), signature_serialization.size());

    if (secp256k1_verify(signature_, hash, private_key_.pubkey)){
        std::cout << "Signature verified from primitives." << "\n" << "\n";
    }

    // Update the input transaction script with the signature and public key
    std::deque<ScriptInput> inputs;
    inputs.push_back(ScriptInput(signature_serialization));
    inputs.push_back(ScriptInput(public_key));
    input_transaction.set_script(Script(inputs));

    // Update the transaction with the signed input
    test_transaction.set_in_txs(std::vector<TxIn>{input_transaction});

    // Validate the transaction
    if (test_transaction.is_valid()){
        std::cout << "Transaction is valid." << "\n" << "\n";
    }

    // Test serialiation upfront
    std::vector<uint8_t> final_result;
    std::vector<uint8_t>::iterator final_result_iterator = final_result.begin();
    test_transaction.serialize(final_result, final_result_iterator);

    std::cout << "serialized transaction: " << "\n";
    HexDump(final_result_iterator, final_result.size());

    // Deserialize and validate the transaction again.
    final_result_iterator = final_result.begin();

    Tx new_transaction(final_result_iterator);

    if (new_transaction.is_valid()){
        std::cout << "serialized Transaction is valid." << "\n" << "\n";
    }
    return 0;
}

int test_a(){
    Tx transaction;

    std::vector<uint8_t> serialization = hex_to_std_vec("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1b03951a0604f15ccf5609013803062b9b5a0100072f425443432f200000000001ebc31495000000001976a9142c30a6aaac6d96687291475d7d52f4b469f665a688ac00000000");

    std::vector<uint8_t>::iterator iterator = serialization.begin();

    transaction.parse(iterator);

    std::cout << "Coinbase transaction: " << (transaction.is_coinbase() ? "True" : "False") << "\n" << "\n" << std::endl;

    auto block_height = transaction.extract_coinbase_block_height();

    if (block_height.has_value()){
        std::cout << "Transaction block height: " << block_height.value() << "\n" << "\n";
    }

    std::vector<uint8_t> serialization2;

    std::vector<uint8_t>::iterator serialization2_iterator = serialization2.begin();


    std::cout << "Reserialization: " << "\n";

    transaction.serialize(serialization2, serialization2_iterator);

    HexDump(serialization2.begin(), serialization2.size());

    return true;
}

int block_test() {
    // Block serialization (example block from Bitcoin mainnet)
    std::string block_hex = "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200000000006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d4c86041b0f2b5710"; // Nonce

    // Convert hex to vector<uint8_t>
    std::vector<uint8_t> block_serialization = hex_to_std_vec(block_hex);
    std::vector<uint8_t>::iterator block_iterator = block_serialization.begin();

    HexDump(block_serialization.begin(), block_serialization.size());

    // parse the block
    Block block(block_serialization.cbegin());

    // Test parsing
    std::cout << "parsed Block:" << std::endl;
    std::cout << "Version: " << block.version << std::endl;
    std::cout << "Previous Block Hash: ";
    HexDump(block.prev_block.cbegin(), block.prev_block.size());
    std::cout << "Merkle Root: ";
    HexDump(block.merkle_root.begin(), block.merkle_root.size());
    std::cout << "Timestamp: " << block.timestamp << std::endl;
    std::cout << "Bits: " << block.bits << std::endl;
    std::cout << "Nonce: " << block.nonce << std::endl;

    // serialize the block
    std::vector<uint8_t> serialized_block;
    std::vector<uint8_t>::iterator serialized_iterator = serialized_block.begin();
    block.serialize(serialized_iterator, serialized_block);

    // Test serialization
    std::cout << "serialized Block:" << std::endl;
    HexDump(serialized_block.cbegin(), serialized_block.size());

    // Check if serialization matches original
    if (serialized_block == block_serialization) {
        std::cout << "Serialization matches original!" << std::endl;
    } else {
        std::cout << "Serialization does not match original!" << std::endl;
    }

    // Test proof-of-work validation
    if (block.check_pow()) {
        std::cout << "Proof-of-Work is valid!" << std::endl;
    } else {
        std::cout << "Proof-of-Work is invalid!" << std::endl;
    }

    // Test difficulty calculation
    uint64_t difficulty = block.difficulty(block.bits);
    std::cout << "Difficulty: " << difficulty << std::endl;

    // Test target manipulation
    std::vector<uint8_t> target = block.bits_to_target(block.bits);
    std::cout << "Target: ";
    HexDump(target.begin(), target.size());

    uint32_t bits_from_target = block.target_to_bits(target);
    std::cout << "Bits from Target: " << std::hex << bits_from_target << std::endl;

    if (bits_from_target == block.bits) {
        std::cout << "Target-to-Bits conversion is correct!" << std::endl;
    } else {
        std::cout << "Target-to-Bits conversion is incorrect!" << std::endl;
    }

    std::vector<uint8_t> first = hex_to_std_vec("000000203471101bbda3fe307664b3283a9ef0e97d9a38a7eacd8800000000000000000010c8aba8479bbaa5e0848152fd3c2289ca50e1c3e58c9a4faaafbdf5803c5448ddb845597e8b0118e43a81d3");
    std::vector<uint8_t>::iterator first_iter = first.begin();
    std::vector<uint8_t> last = hex_to_std_vec("02000020f1472d9db4b563c35f97c428ac903f23b7fc055d1cfc26000000000000000000b3f449fcbe1bc4cfbcb8283a0d2c037f961a3fdf2b8bedc144973735eea707e1264258597e8b0118e5f00474");
    std::vector<uint8_t>::iterator last_iter = last.begin();

    std::vector<uint8_t> next = hex_to_std_vec("0200002099d6a70c547bbaa1a820490bd02cc378d3bc6e20469438010000000000000000b66a0b024cfdf07d0dd97e18ad6ef1a411b0452129d3bfe3e6ebae55defec4dd95425859308d0118bc260a08");
    std::vector<uint8_t>::iterator next_iter = next.begin();

    Block first_block = Block(first_iter);

    Block last_block = Block(last_iter);

    Block next_block = Block(next_iter);

    std::vector<uint8_t> target_2 = Block::calculate_new_target(first_block, last_block);


    std::cout << "New bits: "<< Block::target_to_bits(target_2) << "\n" << "\n";

    std::cout << "Expected bits: "<< next_block.bits << "\n" << "\n";

    std::cout << "Last block version: " << last_block.version << "\n" << "\n";

    std::cout << (last_block.bip_141() ? "BIP 141  is activated" : "BIP 141 is not activated") << "\n" << "\n" ;

    std::cout << (last_block.bip_91() ? "BIP 91 is activated" : "BIP 91 is not activated") << "\n" << "\n" ;

    std::cout << (last_block.bip_9() ? "BIP 9 is activated" : "BIP 9 is not activated") << "\n" << "\n" ;
    return 0;
}


// Test for verifying P2MS (Pay-to-Multisig) transaction parsing and validation
void test_p2ms_transaction() {
    std::string tx_hex = "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b4\
9aa43ad90ba26000000000490047304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac8\
94ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01fffff\
fff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000";

    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(false);

    std::cout << "========== P2MS Transaction ==========" << std::endl;
    std::cout << "Version: " << tx.get_version() << std::endl;
    std::cout << "Locktime: " << tx.get_locktime() << std::endl;
    std::cout << "Number of Inputs: " << tx.get_in_txs().size() << std::endl;
    std::cout << "Number of Outputs: " << tx.get_out_txs().size() << std::endl;
    std::cout << "--------------------------------------" << std::endl;

    // Inputs
    for (size_t i = 0; i < tx.get_in_txs().size(); ++i) {
        TxIn& in = tx.get_in_txs()[i];
        std::cout << "Input #" << i << ":" << std::endl;
        std::cout << "  TxID: ";
        HexDump(in.get_tx_id().begin(), in.get_tx_id().size());
        std::cout << "  Index: " << in.get_tx_index() << std::endl;
        std::cout << "  Sequence: " << in.get_sequence() << std::endl;
        std::cout << "  ScriptSig (" << in.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        in.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "--------------------------------------" << std::endl;

    // Outputs
    for (size_t i = 0; i < tx.get_out_txs().size(); ++i) {
        const TxOut& out = tx.get_out_txs()[i];
        std::cout << "Output #" << i << ":" << std::endl;
        std::cout << "  Amount: " << out.get_amount() << std::endl;
        std::cout << "  ScriptPubKey (" << out.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        out.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "======================================" << std::endl;



    if(tx.is_valid()){
        std::cout << "Transaction is valid." << std::endl;
    }
}

// Test for verifying P2MS (Pay-to-Multisig) transaction parsing and validation
void test_p2sh_transaction() {
    std::string tx_hex = "0100000003a5ee1a0fd80dfbc3142df136ab56e082b799c13aa977c048bdf8f61\
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
a8da127a7dbdd425a05e25f688ac00000000";

    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(false);

    std::cout << "========== P2MS Transaction ==========" << std::endl;
    std::cout << "Version: " << tx.get_version() << std::endl;
    std::cout << "Locktime: " << tx.get_locktime() << std::endl;
    std::cout << "Number of Inputs: " << tx.get_in_txs().size() << std::endl;
    std::cout << "Number of Outputs: " << tx.get_out_txs().size() << std::endl;
    std::cout << "--------------------------------------" << std::endl;

    // Inputs
    for (size_t i = 0; i < tx.get_in_txs().size(); ++i) {
        TxIn& in = tx.get_in_txs()[i];
        std::cout << "Input #" << i << ":" << std::endl;
        std::cout << "  TxID: ";
        HexDump(in.get_tx_id().begin(), in.get_tx_id().size());
        std::cout << "  Index: " << in.get_tx_index() << std::endl;
        std::cout << "  Sequence: " << in.get_sequence() << std::endl;
        std::cout << "  ScriptSig (" << in.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        in.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "--------------------------------------" << std::endl;

    // Outputs
    for (size_t i = 0; i < tx.get_out_txs().size(); ++i) {
        const TxOut& out = tx.get_out_txs()[i];
        std::cout << "Output #" << i << ":" << std::endl;
        std::cout << "  Amount: " << out.get_amount() << std::endl;
        std::cout << "  ScriptPubKey (" << out.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        out.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "======================================" << std::endl;

    

    if(tx.is_valid()){
        std::cout << "Transaction is valid." << std::endl;
    }
}


// Test for verifying P2MS (Pay-to-Multisig) transaction parsing and validation
void test_p2wpkh_transaction() {
    std::string tx_hex = "01000000000101ad2bb91208eef398def3ed3e784d9ee9b7befeb56a3053c35\
61849b88bc4cedf0000000000ffffffff037a3e0100000000001600148d7a0a3461e3891723e5fdf8129caa007\
5060cff7a3e0100000000001600148d7a0a3461e3891723e5fdf8129caa0075060cff0000000000000000256a234\
2697462616e6b20496e632e204a6170616e20737570706f727473205365675769742102483045022100a6e33a7aff\
720ba9f33a0a8346a16fdd022196862796d511d31978c40c9ad48b02206fb8f67bd699a8c952b3386a81d122c366d\
2d36cd08e2de21207e6aa6f96ce9501210283409659355b6d1cc3c32decd5d561abaac86c37a353b52895a5e6c196d6f44800000000";


    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(false);

    std::cout << "========== P2MS Transaction ==========" << std::endl;
    std::cout << "Version: " << tx.get_version() << std::endl;
    std::cout << "Locktime: " << tx.get_locktime() << std::endl;
    std::cout << "Number of Inputs: " << tx.get_in_txs().size() << std::endl;
    std::cout << "Number of Outputs: " << tx.get_out_txs().size() << std::endl;
    std::cout << "--------------------------------------" << std::endl;

    // Inputs
    for (size_t i = 0; i < tx.get_in_txs().size(); ++i) {
        TxIn& in = tx.get_in_txs()[i];
        std::cout << "Input #" << i << ":" << std::endl;
        std::cout << "  TxID: ";
        HexDump(in.get_tx_id().begin(), in.get_tx_id().size());
        std::cout << "  Index: " << in.get_tx_index() << std::endl;
        std::cout << "  Sequence: " << in.get_sequence() << std::endl;
        std::cout << "  ScriptSig (" << in.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        in.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "--------------------------------------" << std::endl;

    // Outputs
    for (size_t i = 0; i < tx.get_out_txs().size(); ++i) {
        const TxOut& out = tx.get_out_txs()[i];
        std::cout << "Output #" << i << ":" << std::endl;
        std::cout << "  Amount: " << out.get_amount() << std::endl;
        std::cout << "  ScriptPubKey (" << out.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        out.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "======================================" << std::endl;

    

    if(tx.is_valid()){
        std::cout << "Transaction is valid." << std::endl;
    }
}

// There are some p2wsh that don't work, e.g those that use multisig(the only ones i have found not to work).
// Test for verifying P2MS (Pay-to-Multisig) transaction parsing and validation
void test_p2wsh_transaction() {
    std::string tx_hex = "020000000001018a39b5cdd48c7d45a31a89cd675a95f5de78aebeeda1e55ac35d7\
110c3bacfc60000000000ffffffff01204e0000000000001976a914ee63c8c790952de677d1f8019c9474d8409\
8d6e188ac0202123423aa20a23421f2ba909c885a3077bb6f8eb4312487797693bbcfe7e311f797e3c5b8fa8700000000";


    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(false);

    std::cout << "========== P2MS Transaction ==========" << std::endl;
    std::cout << "Version: " << tx.get_version() << std::endl;
    std::cout << "Locktime: " << tx.get_locktime() << std::endl;
    std::cout << "Number of Inputs: " << tx.get_in_txs().size() << std::endl;
    std::cout << "Number of Outputs: " << tx.get_out_txs().size() << std::endl;
    std::cout << "--------------------------------------" << std::endl;

    // Inputs
    for (size_t i = 0; i < tx.get_in_txs().size(); ++i) {
        TxIn& in = tx.get_in_txs()[i];
        std::cout << "Input #" << i << ":" << std::endl;
        std::cout << "  TxID: ";
        HexDump(in.get_tx_id().begin(), in.get_tx_id().size());
        std::cout << "  Index: " << in.get_tx_index() << std::endl;
        std::cout << "  Sequence: " << in.get_sequence() << std::endl;
        std::cout << "  ScriptSig (" << in.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        in.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "--------------------------------------" << std::endl;
    // Outputs
    for (size_t i = 0; i < tx.get_out_txs().size(); ++i) {
        const TxOut& out = tx.get_out_txs()[i];
        std::cout << "Output #" << i << ":" << std::endl;
        std::cout << "  Amount: " << out.get_amount() << std::endl;
        std::cout << "  ScriptPubKey (" << out.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        out.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "======================================" << std::endl;

    

    if(tx.is_valid()){
        std::cout << "Transaction is valid." << std::endl;
    }
}

// Test for verifying P2MS (Pay-to-Multisig) transaction parsing and validation
void test_p2wsh_2_transaction() {
    std::string tx_hex = "01000000000101390c5847e5740a9087637787f5a2d616e5976fc64f0e6defc9\
72a1cbc38098e50100000000ffffffff05b0d00800000000001976a9145306faffb8e5d09ea95c56f33bcd8d3e16\
f66ad688acf04902000000000017a914ac62546a0f25a826c785638ed8aad507adb9cdb38723b21400000000001976a\
914d134182663df3bab31881a5b50b1d0deb9aabeb388ac30e60200000000001976a914007303b4eb55d0bad9563dd2a3e\
cdce4b47a79a288ac745f620400000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c\
58d040047304402207b1a0229e1037ec53d3066bd1d73e9dd593df59711f3f0be129f3cb17ef79ecb02200d5561b8c3976c3d\
622ef83afaf410c0b93b3d68795a602e1aa504c3a68c482c0147304402203bee9c5b00e387101d8ac6c1adbca631046a29f28e2\
70e6dbdd3d22cad11216902201bd5632f64b07369e4ba010d1b6d9a4906930807823b1e283f5e2aa1f07541f8016952210375e00\
eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0\
e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000";


    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(false);

    std::cout << "========== P2MS Transaction ==========" << std::endl;
    std::cout << "Version: " << tx.get_version() << std::endl;
    std::cout << "Locktime: " << tx.get_locktime() << std::endl;
    std::cout << "Number of Inputs: " << tx.get_in_txs().size() << std::endl;
    std::cout << "Number of Outputs: " << tx.get_out_txs().size() << std::endl;
    std::cout << "--------------------------------------" << std::endl;

    // Inputs
    for (size_t i = 0; i < tx.get_in_txs().size(); ++i) {
        TxIn& in = tx.get_in_txs()[i];
        std::cout << "Input #" << i << ":" << std::endl;
        std::cout << "  TxID: ";
        HexDump(in.get_tx_id().begin(), in.get_tx_id().size());
        std::cout << "  Index: " << in.get_tx_index() << std::endl;
        std::cout << "  Sequence: " << in.get_sequence() << std::endl;
        std::cout << "  ScriptSig (" << in.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        in.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "--------------------------------------" << std::endl;
    // Outputs
    for (size_t i = 0; i < tx.get_out_txs().size(); ++i) {
        const TxOut& out = tx.get_out_txs()[i];
        std::cout << "Output #" << i << ":" << std::endl;
        std::cout << "  Amount: " << out.get_amount() << std::endl;
        std::cout << "  ScriptPubKey (" << out.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        out.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "======================================" << std::endl;

    

    if(tx.is_valid()){
        std::cout << "Transaction is valid." << std::endl;
    }
}


// Test for verifying P2MS (Pay-to-Multisig) transaction parsing and validation
void test_p2sh_p2wkh_transaction() {
    std::string tx_hex = "020000000001018fa608b5bc62dccfe8044016c4c78adc0e322048f3b0fbd0cc61b7aae0d7befe0\
000000017160014c5ef9be15ad56d39e269158b8de151fefc77d9c60100000001c4782c00000000001976a914674a8527a29f256135\
52267d0edfd181212becdc88ac024730440220079026ade4fba8cc896affedb992bc07251bc93fa310ae9d0e0bfd5340ecf8ee02205f\
4ce3ac1831ed41e20953c461a9f59922953a134362e7c8dd02237e541eec58012102e3592884734ce8431d31348cd16fef8ed943749d65\
1e8c6b27ae8c327db1a91600000000";


    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(false);

    std::cout << "========== P2MS Transaction ==========" << std::endl;
    std::cout << "Version: " << tx.get_version() << std::endl;
    std::cout << "Locktime: " << tx.get_locktime() << std::endl;
    std::cout << "Number of Inputs: " << tx.get_in_txs().size() << std::endl;
    std::cout << "Number of Outputs: " << tx.get_out_txs().size() << std::endl;
    std::cout << "--------------------------------------" << std::endl;

    // Inputs
    for (size_t i = 0; i < tx.get_in_txs().size(); ++i) {
        TxIn& in = tx.get_in_txs()[i];
        std::cout << "Input #" << i << ":" << std::endl;
        std::cout << "  TxID: ";
        HexDump(in.get_tx_id().begin(), in.get_tx_id().size());
        std::cout << "  Index: " << in.get_tx_index() << std::endl;
        std::cout << "  Sequence: " << in.get_sequence() << std::endl;
        std::cout << "  ScriptSig (" << in.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        in.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "--------------------------------------" << std::endl;
    // Outputs
    for (size_t i = 0; i < tx.get_out_txs().size(); ++i) {
        const TxOut& out = tx.get_out_txs()[i];
        std::cout << "Output #" << i << ":" << std::endl;
        std::cout << "  Amount: " << out.get_amount() << std::endl;
        std::cout << "  ScriptPubKey (" << out.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        out.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "======================================" << std::endl;

    

    if(tx.is_valid()){
        std::cout << "Transaction is valid." << std::endl;
    }
}

// Test for verifying P2MS (Pay-to-Multisig) transaction parsing and validation
void test_p2sh_p2wsh_transaction() {
    std::string tx_hex = "01000000000101b2ca63326ca2bd3f234600a947b69264c3f674242e2b\
c0480eccc7141460dccc03000000232200207399bb69ad56fa38b607ea8e1d9cd0039d9572f7a1da109e81\
38ed874a8dab36000000000318138e000000000017a91463726ec3b4193f16dcc046ee2ef223747ee6d7038\
7888a010000000000160014d092e604eabdf15a6dd8e806f5db0b6c25f9b94e8fd1750a0000000017a9140d67\
773a11679be5eafcf525140565525ccd768e870400483045022100fef90b907f4b3627f2483511f5fd00428af8b\
2a313390f0b33436d86982b31f7022037654763701372971e0fc441fdf15a94a72d77bd025e0d4793daedf2467cf3\
830147304402204d15c4de19e48e9b2890d89455d0817ab1d51916ae7957f513332b558a7afc00022022b361fce11c\
4417f240b7aa7d7c569be39f559a887e2ad9881e524a083c3544014752210287913ee7a28340bb536c7ff6ccfd3cf21\
12d9b7783083f459a554982eff84390210362a8997ef839a3282cb6c56a0803ec3da46fc2803742f5924839d42018104b2852ae00000000";


    std::vector<uint8_t> tx_bytes = hex_to_std_vec(tx_hex);
    Tx tx(tx_bytes.cbegin());
    tx.set_testnet(false);

    std::cout << "========== P2MS Transaction ==========" << std::endl;
    std::cout << "Version: " << tx.get_version() << std::endl;
    std::cout << "Locktime: " << tx.get_locktime() << std::endl;
    std::cout << "Number of Inputs: " << tx.get_in_txs().size() << std::endl;
    std::cout << "Number of Outputs: " << tx.get_out_txs().size() << std::endl;
    std::cout << "--------------------------------------" << std::endl;

    // Inputs
    for (size_t i = 0; i < tx.get_in_txs().size(); ++i) {
        TxIn& in = tx.get_in_txs()[i];
        std::cout << "Input #" << i << ":" << std::endl;
        std::cout << "  TxID: ";
        HexDump(in.get_tx_id().begin(), in.get_tx_id().size());
        std::cout << "  Index: " << in.get_tx_index() << std::endl;
        std::cout << "  Sequence: " << in.get_sequence() << std::endl;
        std::cout << "  ScriptSig (" << in.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        in.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "--------------------------------------" << std::endl;
    // Outputs
    for (size_t i = 0; i < tx.get_out_txs().size(); ++i) {
        const TxOut& out = tx.get_out_txs()[i];
        std::cout << "Output #" << i << ":" << std::endl;
        std::cout << "  Amount: " << out.get_amount() << std::endl;
        std::cout << "  ScriptPubKey (" << out.get_script().get_size() << " bytes): ";
        std::vector<uint8_t> script_bytes;
        auto it = script_bytes.begin();
        out.get_script().serialize(script_bytes, it);
        HexDump(script_bytes.begin(), script_bytes.size());
        std::cout << std::endl;
    }

    std::cout << "======================================" << std::endl;

    

    if(tx.is_valid()){
        std::cout << "Transaction is valid." << std::endl;
    }
}
*/