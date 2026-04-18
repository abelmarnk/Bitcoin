#pragma once
#include <cstdint>
#include <vector>
#include "../Murmur/Murmur.h"

constexpr uint32_t BIP37_CONSTANT = 0xfba4c795;

class Bloom {
  public:
	Bloom(uint32_t size, uint32_t hash_count, uint32_t tweak)
	    : bit_field(size * 8, 0), bit_field_size(size * 8), tweak(tweak), hash_count(hash_count) {}

	Bloom() : bit_field_size(0), tweak(0), hash_count(0) {}

	void add(const std::vector<uint8_t>& item) {
		for (uint32_t i = 0; i < hash_count; ++i) {
			uint32_t seed = i * BIP37_CONSTANT + tweak;
			auto start = item.cbegin();
			uint32_t h = MurmurHash(start, static_cast<int>(item.size()), seed);
			uint32_t bit = h % bit_field_size;
			bit_field[bit] = 1;
		}
	}

	// Convert the bit field to bytes for use in FilterLoadMessage.
	std::vector<uint8_t> filter_bytes() const {
		std::vector<uint8_t> bytes((bit_field_size + 7) / 8, 0);
		for (uint32_t i = 0; i < bit_field_size; ++i) {
			if (bit_field[i]) {
				bytes[i / 8] |= (1 << (i % 8));
			}
		}
		return bytes;
	}

	uint32_t get_hash_count() const { return hash_count; }
	uint32_t get_tweak() const { return tweak; }
	uint32_t get_bit_field_size() const { return bit_field_size; }

  private:
	std::vector<uint8_t> bit_field;
	uint32_t bit_field_size;
	uint32_t tweak;
	uint32_t hash_count;
};