#include "../src/Crypt/Crypt.h"
#include <catch/catch_amalgamated.hpp>

bool test_get_hash_160_vs_digeststream() {
    std::vector<std::vector<uint8_t>> test_vectors = {
        {},
        {0x00},
        {0x01, 0x02, 0x03},
        {'p', 'u', 'b', 'k', 'e', 'y'},
        {0xde, 0xad, 0xbe, 0xef}
    };

    for (const auto& input : test_vectors) {
        auto legacy = get_hash_160(input);
        auto streamed = DigestStream<HASH160_tag>::digest(input);
        if (legacy != streamed) {
            std::cout << "Mismatch for input: ";
            HexDump(input.data(), input.size());
            std::cout << "Legacy: ";
            HexDump(legacy.data(), legacy.size());
            std::cout << "Streamed: ";
            HexDump(streamed.data(), streamed.size());

            return false;
        }
        else{
            std::cout << "Match for input: ";
            HexDump(input.data(), input.size());
            std::cout << "Legacy: ";
            HexDump(legacy.data(), legacy.size());
            std::cout << "Streamed: ";
            HexDump(streamed.data(), streamed.size());

        }
    }

    std::cout << "get_hash_160 matches DigestStream<Hash160Tag>::digest\n";

    return true;
}



bool test_get_hash_256_vs_digeststream() {
    std::vector<std::vector<uint8_t>> test_vectors = {
        {},
        {0x00},
        {0x01, 0x02, 0x03},
        {'t', 'e', 's', 't'},
        {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}
    };

    for (const auto& input : test_vectors) {
        auto legacy = get_hash_256(input);
        auto streamed = DigestStream<HASH256_tag>::digest(input);
        if (legacy != streamed) {
            std::cout << "Mismatch for input: ";
            HexDump(input.data(), input.size());
            std::cout << "Legacy: ";
            HexDump(legacy.data(), legacy.size());
            std::cout << "Streamed: ";
            HexDump(streamed.data(), streamed.size());

            return false;
        }
        else{
            std::cout << "Match for input: ";
            HexDump(input.data(), input.size());
            std::cout << "Legacy: ";
            HexDump(legacy.data(), legacy.size());
            std::cout << "Streamed: ";
            HexDump(streamed.data(), streamed.size());

        }
    }

    std::cout << "get_hash_256 matches DigestStream<Hash256Tag>::digest\n";
    return true;
}

bool test_get_sha_256_vs_streaming() {
    std::vector<std::vector<uint8_t>> test_vectors = {
        {},
        {0x00},
        {0x01, 0x02, 0x03},
        {'h', 'a', 's', 'h'},
        {0xaa, 0xbb, 0xcc, 0xdd, 0xee}
    };

    for (const auto& input : test_vectors) {
        auto legacy = get_sha_256(input);

        DigestStream<SHA256_tag> stream;

        // Split the input into 2 parts for streaming simulation
        auto mid = input.size() / 2;
        stream.update({input.data(), mid});
        stream.update({input.data() + mid, input.size() - mid});

        auto streamed = stream.finalize();

        if (legacy != streamed) {
            std::cout << "Mismatch for input: ";
            HexDump(input.data(), input.size());
            std::cout << "Legacy: ";
            HexDump(legacy.data(), legacy.size());
            std::cout << "Streamed: ";
            HexDump(streamed.data(), streamed.size());

            return false;
        }
        else{
            std::cout << "Match for input: ";
            HexDump(input.data(), input.size());
            std::cout << "Legacy: ";
            HexDump(legacy.data(), legacy.size());
            std::cout << "Streamed: ";
            HexDump(streamed.data(), streamed.size());

        }
    }

    std::cout << "get_sha_256 matches streamed DigestStream<SHA256_tag>\n";
    return true;
}

bool test_get_hash160_vs_streaming() {
    std::vector<std::vector<uint8_t>> test_vectors = {
        {},
        {0x01},
        {0x01, 0x02, 0x03, 0x04},
        {'s', 'e', 'g', 'w', 'i', 't'},
        {0xde, 0xad, 0xbe, 0xef}
    };

    for (const auto& input : test_vectors) {
        auto legacy = get_hash_160(input);

        DigestStream<HASH160_tag> stream;

        auto mid = input.size() / 2;
        stream.update({input.data(), mid});
        stream.update({input.data() + mid, input.size() - mid});

        auto streamed = stream.finalize();

        if (legacy != streamed) {
            std::cout << "Mismatch for input: ";
            HexDump(input.data(), input.size());
            std::cout << "Legacy: ";
            HexDump(legacy.data(), legacy.size());
            std::cout << "Streamed: ";
            HexDump(streamed.data(), streamed.size());

            return false;
        }
        else{
            std::cout << "Match for input: ";
            HexDump(input.data(), input.size());
            std::cout << "Legacy: ";
            HexDump(legacy.data(), legacy.size());
            std::cout << "Streamed: ";
            HexDump(streamed.data(), streamed.size());

        }
    }

    std::cout << "get_hash_160 matches streamed DigestStream<HASH160_tag>\n";
    return true;
}

bool test_get_hash256_vs_streaming() {
    std::vector<std::vector<uint8_t>> test_vectors = {
        {0xff, 0xff, 0xff, 0xff},
        {0x01},
        {0x00},
        {0x11},
        {0x01, 0x02, 0x03, 0x04},
        {'b', 'i', 't', 'c', 'o', 'i', 'n'},
        {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
    };

    for (const auto& input : test_vectors) {
        auto legacy = get_hash_256(input);

        DigestStream<HASH256_tag> stream;

        //auto mid = input.size() / 2;
        //stream.update({input.data(), mid});
        //stream.update({input.data() + mid, input.size() - mid});

        stream.update({input.data(), input.size()});

        auto streamed = stream.finalize();

        if (legacy != streamed) {
            std::cout << "Mismatch for input: ";
            HexDump(input.data(), input.size());
            std::cout << "Legacy: ";
            HexDump(legacy.data(), legacy.size());
            std::cout << "Streamed: ";
            HexDump(streamed.data(), streamed.size());

            return false;
        }
        else{
            std::cout << "Match for input: ";
            HexDump(input.data(), input.size());
            std::cout << "Legacy: ";
            HexDump(legacy.data(), legacy.size());
            std::cout << "Streamed: ";
            HexDump(streamed.data(), streamed.size());

        }
    }

    std::cout << "get_hash_256 matches streamed DigestStream<HASH256_tag>\n";
    return true;
}



TEST_CASE("DigestStream", "[digest][HASH150_tag]") {
    REQUIRE(test_get_hash_160_vs_digeststream());
}

TEST_CASE("DigestStream", "[digest][HASH256_tag]") {
    REQUIRE(test_get_hash_256_vs_digeststream());
}

TEST_CASE("DigestStream manual update vs get_sha_256", "[digest][SHA256_tag]") {
    REQUIRE(test_get_sha_256_vs_streaming());
}

TEST_CASE("DigestStream manual update vs get_hash160", "[digest][HASH160_tag]") {
    REQUIRE(test_get_hash160_vs_streaming());
}

TEST_CASE("DigestStream manual update vs get_hash256", "[digest][HASH256_tag]") {
    REQUIRE(test_get_hash256_vs_streaming());
}