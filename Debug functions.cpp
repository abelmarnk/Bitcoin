#include <iostream>
#include <vector>
#include <string>
#include <iomanip>


void HexDump(std::vector<uint8_t>::iterator Start, size_t Size) {

	while (Size > 0) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << *Start * 1;
		Size--;
		Start++;
	}

	std::cout << "\n" << "\n";
}