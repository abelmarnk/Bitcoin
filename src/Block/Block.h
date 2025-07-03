#pragma once

#include <cmath>
#include <vector>
#include <algorithm>
#include "../Crypt/Crypt.h"
#include "../Varint/Varint.h"
#include "../Debug functions/Debug functions.h"
class Block
{
public:
    Block() : version(0), timestamp(0), bits(0), nonce(0) {

    }

    Block(uint32_t version,
          const std::array<uint8_t, 32> &prev_block,
          const std::array<uint8_t, 32> &merkle_root,
          uint32_t timestamp,
          uint32_t bits,
          uint32_t nonce)
        : version(version),
          prev_block(prev_block),
          merkle_root(merkle_root),
          timestamp(timestamp),
          bits(bits),
          nonce(nonce) {
    }

    Block(std::vector<uint8_t>::const_iterator&& start){
        parse(std::forward<std::vector<uint8_t>::const_iterator>(start));
    }

    // Parses the block from an iterator over some bytes.
    void parse(std::vector<uint8_t>::const_iterator&&);

    // Serializes the block into a vector of bytes starting at "start".
    void serialize(std::vector<uint8_t>::iterator &start, std::vector<uint8_t> &input, bool should_adjust_iterator = true) const;

    void serialize(std::vector<uint8_t>& result, bool should_adjust_iterator = true) const{
		auto iterator = result.begin();
		serialize(iterator, result, should_adjust_iterator);
	}

    std::vector<uint8_t> get_hash() const {
        // Get the block serialization.
        std::vector<uint8_t> serialization;
        auto serialization_iterator = serialization.begin();
        serialize(serialization_iterator, serialization);
        // Return the hash 256 to those bytes.
        return DigestStream<HASH256_tag>::digest(serialization);
    }

     // Get the target(the sequence of bytes a block serialization hash is compared against to 
     // affirm the proof of work) from the bits(the 4 bytes encoding the target).
    static std::vector<uint8_t> bits_to_target(uint32_t bits);

    // Returns the difficulty as an integer approximation.
    static uint64_t difficulty(uint32_t bits) {
        std::vector<uint8_t> target = bits_to_target(bits);

        BigNum max_target = BigNum(0xffff) * (BigNum(256) ^ (0x1d - 3));

        BigNum current_target = BigNum(target);
        
        if (current_target > max_target) {
            return 1;
        }
        
        return (max_target / current_target).get_unsigned_small();
    }

    // Check the proof of work assoiated with a particular block.
    bool check_pow() const;

    // Get the bits(the 4 bytes encoding the target) from the
    // target(the sequence of bytes a block serialization hash is compared against to affirm the proof of work).
    static uint32_t target_to_bits(const std::vector<uint8_t> &target);

    // Calculate the target for the block immediately after last_block(if the block height of last_block is x, 
    // then the target is for the block with height x + 1).
    static std::vector<uint8_t> calculate_new_target(const Block &first_block, const Block &last_block);

    // Check support for bip 9
    bool bip_9() const {
        return (version & 0xE0000000) == 0x20000000;
    }

    // Check support for bip 91
    bool bip_91() const {
        return (version & 0x10) != 0;
    }

    // Check support for bip 141
    bool bip_141() const {
        return (version & 0x2) != 0;
    }

    // Get the size in bytes of the serialization of the block.
    uint64_t get_size() const{
        return sizeof(version) + sizeof(prev_block) + sizeof(merkle_root) + sizeof(timestamp) +
                sizeof(bits) + sizeof(nonce);
    }

    uint32_t version;
    std::array<uint8_t, 32> prev_block;
    std::array<uint8_t, 32> merkle_root;
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
};