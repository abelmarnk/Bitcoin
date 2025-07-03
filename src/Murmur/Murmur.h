#pragma once
#include <vector>
#include <cstdint>
uint32_t MurmurHash(std::vector<uint8_t>::const_iterator& start, int len, uint32_t seed);
