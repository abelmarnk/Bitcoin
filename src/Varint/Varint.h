#pragma once
#include <vector>
#include "../Compute/Compute.h"
typedef BigNum Variant;
uint64_t parse_varint(std::vector<uint8_t>::const_iterator&& start);
uint32_t get_varint_byte_size(uint64_t Number);
std::vector<uint8_t>::iterator serialize_varint(uint64_t Number, std::vector<uint8_t>& input, bool should_adjust_iterator = true);
std::vector<uint8_t>::iterator serialize_varint(uint64_t Number, std::vector<uint8_t>::iterator& start,
                                 std::vector<uint8_t>& input, bool should_adjust_iterator = true);
