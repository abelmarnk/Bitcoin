#include<iostream>
#include "Block.h"
#include "../Debug functions/Debug functions.h"
#include "../Serial/Serial.h"

void Block::parse(std::vector<uint8_t>::const_iterator &&start){
    // The bytes in "start" are expected to be in little endian.
    // The iterator is advanced after each read

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), version);

    std::copy(start, start + prev_block.size(), prev_block.begin());
    start += prev_block.size();

    std::copy(start, start + merkle_root.size(), merkle_root.begin());
    start += merkle_root.size();

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), timestamp);

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), bits);

    read_int_from_little_endian_bytes(std::forward<std::vector<uint8_t>::const_iterator>(start), nonce);
}

void Block::serialize(std::vector<uint8_t>::iterator &start, std::vector<uint8_t> &input, bool should_adjust_iterator) const{
    // The bytes are serialized in little endian. 
    // The iterator is advanced after each write

    if(should_adjust_iterator){
        adjust_bytes(start, input, get_size());
    }

    write_int_as_little_endian_bytes(version, start, input);

    start = std::copy(prev_block.begin(), prev_block.end(), start);

    start = std::copy(merkle_root.begin(), merkle_root.end(), start);

    write_int_as_little_endian_bytes(timestamp, start, input);

    write_int_as_little_endian_bytes(bits, start, input);

    write_int_as_little_endian_bytes(nonce, start, input);
}

std::vector<uint8_t> Block::bits_to_target(uint32_t bits){
    // Bits: exponent-(1 byte) coefficient-(3 bytes).

    uint32_t exponent = bits >> 24;
    uint32_t coefficient = bits & 0x00'7F'FF'FF; // Only lower 23 bits are used for coefficient.

    std::vector<uint8_t> target(32, 0); // 256 bits // Only lower 23 bits are used for coefficient.

    if (exponent <= 3) {
        uint32_t value = coefficient >> (8 * (3 - exponent));
        for (int counter = 0; counter < exponent; ++counter) {
            target[31 - counter] = (value >> (8 * counter)) & 0xff; // Extract bits from value and store it in target.
        }
    }
    else {
        // Extract bits from coeffficient and store it in target.
        target[32 - exponent] = (coefficient >> 16) & 0xff;
        target[32 - exponent + 1] = (coefficient >> 8) & 0xff;
        target[32 - exponent + 2] = coefficient & 0xff;
    }

    //IMPORTANT
    // Target is returned as a big-endian.
    return target;
}

bool Block::check_pow() const{

    std::vector<uint8_t> hash = get_hash();
    
    std::vector<uint8_t> target = bits_to_target(bits);

    for (size_t counter = 0; counter < hash.size(); ++counter){
        // The hash is by convention in little-endian, so we reverse it to get the big-endian equivalent.
        if (hash[(hash.size() - 1) - counter] < target[counter]){
            return true;
        }
        if (hash[(hash.size() - 1) - counter] > target[counter]){
            return false;
        }
    }
    return true; // The hash equals the target.
}

uint32_t Block::target_to_bits(const std::vector<uint8_t> &target){
    
    //IMPORTANT
    // Target is assumed to be in little-endian.

    // Bits: exponent-(1 byte) coefficient-(3 bytes).

    // Find first non-zero byte
    size_t counter = 0;
    while (counter < target.size() && target[counter] == 0){
        ++counter;
    }

    uint32_t exponent = static_cast<uint32_t>(target.size() - counter);
    uint32_t coefficient = 0;

    if (exponent >= 3) {
        // Extract the first 3 bytes from target
        coefficient = (target[counter] << 16);
        coefficient |= (target[counter + 1] << 8);
        coefficient |= (target[counter + 2]);
    }
    else if (exponent == 2) {
        // Extract the first 2 bytes from target
        coefficient = (target[counter] << 8);
        coefficient |= (target[counter + 1]);
        coefficient <<= 8;
    }
    else if (exponent == 1) {
        // Extract a single byte from target
        coefficient = static_cast<uint32_t>(target[counter]) << 16;
    }
    else{
        coefficient = 0;
        exponent = 0;
    }

    if (coefficient & 0x00800000){
        // If the coefficient is signed (coeffficeint >= 0x00800000), then we would have to store it as an
        // unsigned instead as the number is taken to be an unsigned and though the last byte of the coefficeint is
        // set to zero(It's not really truncated or cut short since the exponent is adjusted), it does not affect the 
        // proof of work if the bits encoded the target for a block since the number making the number smaller, can only 
        // mean more effort was put into making the block, going by the way the proof of work works on Bitcoin.
        // If the target was derived to have a block created against it, the miner would already have it at hand and work with it.
        coefficient >>= 8;
        exponent += 1;
    }

    return (exponent << 24) | (coefficient & 0x007fffff); // Set them in their position.
}

std::vector<uint8_t> Block::calculate_new_target(const Block &first_block, const Block &last_block){
    
    constexpr uint32_t TWO_WEEKS = 14 * 24 * 60 * 60; // In seconds.

    uint32_t time_differential = last_block.timestamp - first_block.timestamp;

    if (time_differential > TWO_WEEKS * 4) {
        time_differential = TWO_WEEKS * 4; // Only allow a maximum scale up of 4
    }
    if (time_differential < TWO_WEEKS / 4) {
        time_differential = TWO_WEEKS / 4; // Only allow a maximum scale down of 4.
    }

    // We reduce possible rounding errors by converting to target, using Openssl and performing the multiplication first.
    return ((BigNum(last_block.bits_to_target(last_block.bits)) * 
    BigNum(time_differential)) / 
    TWO_WEEKS).to_std_vec();  // Calculate the new bits.
}