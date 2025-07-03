#pragma once
#include <bitset>
#include <cstdint>
#include <vector>
#include "../Murmur/Murmur.h"
constexpr uint32_t BIP37_CONSTANT = 0xfba4c795;

class Bloom{
    Bloom(std::bitset<64>& bits, uint32_t bits_field_size, uint32_t tweak, uint32_t repeat_count):
    bits(bits), bits_field_size(bits_field_size), tweak(tweak), repeat_count(repeat_count){

    }

    Bloom(){

    }

    uint32_t add(const std::vector<uint8_t>& input){
        for (uint32_t counter = 0; counter < repeat_count; ++counter){
            uint32_t seed = ((counter + 1) * 0xfba4c795) + tweak;

            auto result = MurmurHash(input.cbegin(), counter, seed);

            auto bit_position = result % bits_field_size;

            return bits[bit_position];
        }
    }

    uint32_t tweak;
    uint32_t repeat_count;
    std::bitset<64> bits;
    uint32_t bits_field_size;
};