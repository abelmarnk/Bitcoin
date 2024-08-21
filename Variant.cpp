#include "Variant.h"

Variant ParseVariant(std::vector<uint8_t>::iterator& Start) {
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


	uint8_t Number = *Start;
	std::vector<uint8_t> Value;

	Start++;

	if (Number == 0xfd) {
		Value = std::move(std::vector<uint8_t>(Start, Start + 2));
		Start += 2;
	}
	else
		if (Number == 0xfe) {
			Value = std::move(std::vector<uint8_t>(Start, Start + 4));
			Start += 4;
		}
		else
			if (Number == 0xff) {
				Value = std::move(std::vector<uint8_t>(Start, Start + 8));
				Start += 8;
			}
			else {
				Value = { Number };
			}

	std::reverse(Value.begin(), Value.end()); // The value of the variant is stored in a little-endian, so convert to big-endian.

	return Value;
}

std::vector<uint8_t>::iterator ParseVariant(Variant Number, std::vector<uint8_t>::iterator& Start, std::vector<uint8_t>& Input) {
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

	std::vector<uint8_t> Vector(std::move(Number.ToStdVec()));

	std::reverse(Vector.begin(), Vector.end()); // The value of the variant is stored in a little-endian.

	if (Number >= 0xfd && Number < std::numeric_limits<uint16_t>::max()) {
		Vector.insert(Vector.begin(), 0xfd);
	}
	else
		if (Number >= std::numeric_limits<uint16_t>::max() && Number < std::numeric_limits<uint32_t>::max()) {
			Vector.insert(Vector.begin(), 0xfe);
		}
		else
			if (Number >= std::numeric_limits<uint32_t>::max() && Number < std::numeric_limits<uint64_t>::max()) {
				Vector.insert(Vector.begin(), 0xff);
			}

	Start = Input.insert(Start, Vector.begin(), Vector.end());
	Start += Vector.end() - Vector.begin();
	return Start;
}
