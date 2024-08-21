#include <vector>
#include "Compute.h"
typedef BigNum Variant;
Variant ParseVariant(std::vector<uint8_t>::iterator& Start);
std::vector<uint8_t>::iterator ParseVariant(Variant Number, std::vector<uint8_t>::iterator& Start, std::vector<uint8_t>& Input);
