#pragma once
#include "../Error/Error.h"
#include <unordered_map>
#include <iomanip>
#include <concepts>
#include <vector>
#include <iterator>
#include <algorithm>

std::vector<uint8_t> hex_to_std_vec(const std::string& hex);

template <std::size_t Size>
std::array<uint8_t, Size> hex_to_std_array(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw ParsingError(ParsingError::Type::INVALID_DATA, 
            "The string provided is not a valid hex value.");
    }

    std::size_t byte_len = hex.size() / 2;

    if (byte_len > Size) {
        throw ParsingError(ParsingError::Type::OUT_OF_BOUNDS);
    }

    std::array<uint8_t, Size> bin{};
    auto hex_to_byte = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw ParsingError(ParsingError::Type::INVALID_DATA, 
            "Invalid hex character.");
    };

    for (std::size_t i = 0; i < byte_len; ++i) {
        uint8_t high = hex_to_byte(hex[2 * i]);
        uint8_t low  = hex_to_byte(hex[2 * i + 1]);
        bin[i] = (high << 4) | low;
    }

    return bin;
}

inline std::string std_vec_to_hex(const std::vector<uint8_t>& vector_bytes);

template <std::size_t Size>
inline std::string std_array_to_hex(const std::array<uint8_t, Size>& array_bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : array_bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::string bin_to_base_58(const std::vector<uint8_t>& vec);

std::vector<uint8_t> base_58_to_bin(std::string hex);

std::string encode_to_bitcoin_address(const std::vector<uint8_t>& sec, bool testnet);

std::vector<uint8_t> decode_from_bitcoin_address(const std::string& address);

std::string encode_to_wif(std::vector<uint8_t> sec, bool compressed, bool testnet);

std::vector<uint8_t> decode_from_wif(std::string address);

template <std::integral T>
T read_int_from_little_endian_bytes(std::vector<uint8_t>::const_iterator& iterator) {

    T result = 0;
    for (std::size_t counter = 0; counter < sizeof(T); ++counter) {
        result |= static_cast<T>(*iterator) << (8 * counter); // Extract the bytes and put it in the 
                                                              // appropriate position.
        iterator++;
    }
    return result;
}

template <std::integral T>
void read_int_from_little_endian_bytes(std::vector<uint8_t>::const_iterator&& iterator, T& value) {

    value = 0;

    for (std::size_t counter = 0; counter < sizeof(T); ++counter) {
        value |= static_cast<T>(*iterator) << (8 * counter); // Extract the bytes and put it in the 
                                                              // appropriate position.
        iterator++;
    }
}


template <std::integral T>
void read_int_from_big_endian_bytes(std::vector<uint8_t>::const_iterator&& iterator, T& value) {

    value = 0;

    for (std::size_t counter = 0; counter < sizeof(T); ++counter) {
        value |= static_cast<T>(*iterator) << (8 * ((sizeof(T) - 1) - counter)); // Extract the bytes and put it in the 
                                                              // appropriate position.
        iterator++;
    }
}


template <std::integral T>
void write_int_as_little_endian_bytes(T value, std::vector<uint8_t>::iterator& iterator, std::vector<uint8_t>& vector) {

    for (std::size_t counter = 0; counter < sizeof(T); ++counter) {
        *iterator = static_cast<uint8_t>(value >> (8 * counter)); // Extract the bytes and put it in the
                                                                    // appropriate position.
        iterator++;
    }
}

template <std::integral T>
void write_int_as_big_endian_bytes(T value, std::vector<uint8_t>::iterator& iterator, std::vector<uint8_t>& vector) {

    for (std::size_t counter = 0; counter < sizeof(T); ++counter) {
        *iterator = static_cast<uint8_t>(value >> (8 * ((sizeof(T) - 1) - counter))); // Extract the bytes and put it in the
                                                                    // appropriate position.
        iterator++;
    }
}


template <std::integral T>
std::vector<uint8_t> base_int_to_big_endian_bytes(T value, bool pad_to_size) {
    std::vector<uint8_t> bytes;

    if(value == 0){
        return std::vector<uint8_t>((pad_to_size ? sizeof(T): 1), 0x00);
    }

    for (std::size_t counter = 0; counter < sizeof(T); ++counter) {
        uint8_t byte = static_cast<uint8_t>(value >> (8 * ((sizeof(T) - 1) - counter)));
        if (pad_to_size || byte != 0 || !bytes.empty()) {
            bytes.push_back(byte);
        }
    }
    
    return bytes;
}

template <std::integral T>
std::vector<uint8_t> base_int_to_little_endian_bytes(T value, bool pad_to_size) {
    std::vector<uint8_t> bytes(base_int_to_big_endian_bytes(value, pad_to_size));

    std::reverse(bytes.begin(), bytes.end());

    return bytes;
}

template <std::integral T>
std::vector<uint8_t> int_to_big_endian_bytes_pad(T value) {
    return base_int_to_big_endian_bytes<T>(value, true);
}

template <std::integral T>
std::vector<uint8_t> int_to_big_endian_bytes_no_pad(T value) {
    return base_int_to_big_endian_bytes<T>(value, false);
}

template <std::integral T>
std::vector<uint8_t> int_to_little_endian_bytes_pad(T value) {
    return base_int_to_little_endian_bytes<T>(value, true);
}

template <std::integral T>
std::vector<uint8_t> int_to_little_endian_bytes_no_pad(T value) {
    return base_int_to_little_endian_bytes<T>(value, false);
}


template <std::integral T>
T little_endian_bytes_to_int(const std::vector<uint8_t>& bytes){

        T result = T();

        for(auto byte_iterator = bytes.rbegin(); byte_iterator != bytes.rend(); byte_iterator++){
            result << 8;
            result += *byte_iterator;
        }

        return result;
}

template <std::integral T>
T big_endian_bytes_to_int(const std::vector<uint8_t>& bytes){

        T result = T();

        for(auto byte_iterator = bytes.begin(); byte_iterator != bytes.end(); byte_iterator++){
            result << 8;
            result += *byte_iterator;
        }

        return result;
}


void adjust_bytes(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, uint32_t serialization_size);

