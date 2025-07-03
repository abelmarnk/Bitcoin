#pragma once
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <concepts>

template <std::forward_iterator Iterator>
void HexDump(Iterator start, size_t size) {

	while (size > 0) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << *start * 1;
		size--;
		start++;
	}

	std::cout << "\n" << "\n";
}