#include <cstdint>
#include <cstring>
#include <vector>
#include "../Murmur/Murmur.h"

// MurmurHash3 32-bit
uint32_t MurmurHash(std::vector<uint8_t>::const_iterator& start, int len, uint32_t seed) {
    auto data = start;

    const int nblocks = len / 4;

    uint32_t h1 = seed;

    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    // body
    std::vector<uint8_t>::const_iterator blocks = (data + nblocks * 4);
    for (int i = -nblocks; i; i++) {
        uint32_t k1 = 0;
        k1 |= blocks[4 * i];
        k1 |= blocks[4 * i + 1] << 8;
        k1 |= blocks[4 * i + 2] << 16;
        k1 |= blocks[4 * i + 3] << 24;

        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> (32 - 15));
        k1 *= c2;

        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> (32 - 13));
        h1 = h1 * 5 + 0xe6546b64;
    }

    // tail
    std::vector<uint8_t>::const_iterator tail = data + nblocks * 4;
    uint32_t k1 = 0;

    switch (len & 3) {
        case 3: k1 ^= tail[2] << 16;
        case 2: k1 ^= tail[1] << 8;
        case 1: k1 ^= tail[0];
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >> (32 - 15));
                k1 *= c2;
                h1 ^= k1;
    }

    // finalization
    h1 ^= len;

    // fmix32
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}
