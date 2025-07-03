#include "Varint.h"
#include "../Serial/Serial.h"
#include "../Debug functions/Debug functions.h"
#include <algorithm>

uint64_t parse_varint(std::vector<uint8_t>::const_iterator&& start) {
	// The magic constants used here, are markers used for signifying the size represented by a variant, i could not think of an appropriate name
// so I left them magical, they are described as follows:-
//
// A prefix of less than 0xfd is taken as the actual value, that is [0,253)
// 0xfd :- this is for when the value stored is equal to or greater than 253 or 0xfd, the value after the prefix taken as it is
// and is expected to be [0xfd,std::numeric_limits<uint16_t>::max())
// 0xfe :- this is for when the value stored is equal to or greater than std::numeric_limits<uint16_t>::max(), the value after the prefix taken as it is
// and is expected to be [std::numeric_limits<uint16_t>::max(),std::numeric_limits<uint32_t>::max())
// 0xff :- this is for when the value stored is equal to or greater than std::numeric_limits<uint32_t>::max(), the value after the prefix taken as it is
// and is expected to be [std::numeric_limits<uint32_t>::max(),std::numeric_limits<uint64_t>::max())


	uint8_t Number = *start;
	std::vector<uint8_t> Value;

	start++;

	if (Number == 0xfd) {
		Value = std::move(std::vector<uint8_t>(start, start + 2));
		start += 2;
	}
	else
		if (Number == 0xfe) {
			Value = std::move(std::vector<uint8_t>(start, start + 4));
			start += 4;
		}
		else
			if (Number == 0xff) {
				Value = std::move(std::vector<uint8_t>(start, start + 8));
				start += 8;
			}
			else {
				Value = { Number };
			}

	

	return little_endian_bytes_to_int<uint64_t>(Value);
}

uint32_t get_varint_byte_size(uint64_t Number) {
	// The magic constants used here, are markers used for signifying the size represented by a variant, i could not think of an appropriate name
	// so I left them magical, they are described as follows:-
	//
	// A prefix of less than 0xfd is taken as the actual value, that is [0,253)
	// 0xfd :- this is for when the value stored is equal to or greater than 253 or 0xfd, the value after the prefix taken as it is
	// and is expected to be [0xfd,std::numeric_limits<uint16_t>::max())
	// 0xfe :- this is for when the value stored is equal to or greater than std::numeric_limits<uint16_t>::max(), the value after the prefix taken as it is
	// and is expected to be [std::numeric_limits<uint16_t>::max(),std::numeric_limits<uint32_t>::max())
	// 0xff :- this is for when the value stored is equal to or greater than std::numeric_limits<uint32_t>::max(), the value after the prefix taken as it is
	// and is expected to be [std::numeric_limits<uint32_t>::max(),std::numeric_limits<uint64_t>::max())

	if (Number < 0xfd) {
		return 1;
	}
	else
		if (Number < std::numeric_limits<uint16_t>::max()) {
			return 3;
		}
		else
			if (Number < std::numeric_limits<uint32_t>::max()) {
				return 5;
			}
			else {
				return 9;
			}
}

std::vector<uint8_t>::iterator serialize_varint(uint64_t Number, std::vector<uint8_t>& input, bool should_adjust_iterator) {
	auto iterator = input.begin();
	return serialize_varint(Number, iterator, input, should_adjust_iterator);
}
std::vector<uint8_t>::iterator serialize_varint(uint64_t Number, std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, bool should_adjust_iterator) {
	// The magic constants used here, are markers used for signifying the size represented by a variant, i could not think of an appropriate name
	// so I left them magical, they are described as follows:-
	//
	// A prefix of less than 0xfd is taken as the actual value, that is [0,253)
	// 0xfd :- this is for when the value stored is equal to or greater than 253 or 0xfd, the value after the prefix taken as it is
	// and is expected to be [0xfd,std::numeric_limits<uint16_t>::max())
	// 0xfe :- this is for when the value stored is equal to or greater than std::numeric_limits<uint16_t>::max(), the value after the prefix taken as it is
	// and is expected to be [std::numeric_limits<uint16_t>::max(),std::numeric_limits<uint32_t>::max())
	// 0xff :- this is for when the value stored is equal to or greater than std::numeric_limits<uint32_t>::max(), the value after the prefix taken as it is
	// and is expected to be [std::numeric_limits<uint32_t>::max(),std::numeric_limits<uint64_t>::max())

	if(should_adjust_iterator){
		adjust_bytes(start, input, get_varint_byte_size(Number));
	}

	std::vector<uint8_t> Vector(int_to_little_endian_bytes_no_pad(Number));

	if (Number >= 0xfd && Number < std::numeric_limits<uint16_t>::max()) {
		*start = 0xfd;
		start++;			
	}
	else
		if (Number >= std::numeric_limits<uint16_t>::max() && Number < std::numeric_limits<uint32_t>::max()) {
			*start = 0xfe;
			start++;			
		}
		else
			if (Number >= std::numeric_limits<uint32_t>::max() && Number < std::numeric_limits<uint64_t>::max()) {
				*start = 0xff;
				start++;			
			}

	start = std::copy(Vector.begin(), Vector.end(), start);
	return start;
}
