#include <iomanip>
#include <iostream>
#include "../Crypt/Crypt.h"
#include "../Debug functions/Debug functions.h"
#include <unordered_map>
#include <algorithm>

std::vector<uint8_t> hex_to_std_vec(const std::string& hex) {

	if(hex.size() % 2 != 0){
		throw ParsingError(ParsingError::Type::INVALID_DATA, 
			"The string provided is not a valid hex value.");
	}

	
    std::vector<uint8_t> bin(hex.size()/2);
	
	auto bin_iterator = bin.begin();
	
    uint8_t temp = 0;

    std::string::const_iterator hex_iterator = hex.cbegin();

    while (hex_iterator != hex.cend()) {
        temp = 0;

        if (*hex_iterator >= '0' && *hex_iterator <= '9') {
            temp = 16 * ((*hex_iterator) - '0');
        }
        else
            if (*hex_iterator >= 'a' && *hex_iterator <= 'f') {
                temp = 16 * (((*hex_iterator) - 'a') + 10);
            }
            else
                if (*hex_iterator >= 'A' && *hex_iterator <= 'F') {
                    temp = 16 * (((*hex_iterator) - 'A') + 10);
                }
                else
                    throw ParsingError(ParsingError::Type::INVALID_DATA, 
                        "The string provided is not a valid hex value.");

        hex_iterator++;

        if (*hex_iterator >= '0' && *hex_iterator <= '9') {
            temp += ((*hex_iterator) - '0');
        }
        else
            if (*hex_iterator >= 'a' && *hex_iterator <= 'f') {
                temp += (((*hex_iterator) - 'a') + 10);
            }
            else
                if (*hex_iterator >= 'A' && *hex_iterator <= 'F') {
                    temp += (((*hex_iterator) - 'A') + 10);
                }
                else
                    throw ParsingError(ParsingError::Type::INVALID_DATA, 
                        "The string provided is not a valid hex value.");
        hex_iterator++;

        *bin_iterator = temp;
		++bin_iterator;
    }

    return bin;
}

inline std::string std_vec_to_hex(const std::vector<uint8_t>& vector_bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : vector_bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::string bin_to_base_58(const std::vector<uint8_t>& Vec) {
	std::string Base58_Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	BigNum Bin(Vec);

	std::string Base58Result;

	while (Bin > 0) {
		Base58Result.push_back(Base58_Alphabet[(Bin % 58).get_unsigned_small()]);
		Bin = Bin / 58;
	}

	std::vector<uint8_t>::const_iterator VectorIterator = Vec.begin();

	while (*VectorIterator == 0x00) {
		Base58Result.push_back(Base58_Alphabet[0]);
		VectorIterator++;
	}

	std::reverse(Base58Result.begin(), Base58Result.end());

	return Base58Result;
}

std::vector<uint8_t> base_58_to_bin(std::string Hex) {
	std::string Base58_Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	std::unordered_map<uint8_t, uint8_t> LetterToNumber;

	for (size_t counter = 0; counter < Base58_Alphabet.size(); ++counter) {
		LetterToNumber.emplace(Base58_Alphabet[counter], counter);
	}

	BigNum Number = 0;

	//std::reverse(Hex.begin(), Hex.end());

	for (size_t counter = 0; counter < Hex.size(); ++counter) {
		Number = (Number * 58) + LetterToNumber[Hex[counter]];
	}

	std::vector<uint8_t> Result = Number.to_std_vec();

	std::string::const_iterator Iterator = Hex.begin();

	while (*Iterator == Base58_Alphabet[0]) {
		Result.insert(Result.begin(), 0x00);
		Iterator++;
	}

	return Result;
}
std::string encode_to_bitcoin_address(const std::vector<uint8_t>& bytes, bool Testnet) {

	std::vector<uint8_t> Hash160 = DigestStream<HASH160_tag>::digest(std::span<const uint8_t>(bytes.data(), bytes.size()));

	if (Hash160.empty())
		return std::string();

	Hash160.insert(Hash160.begin(), (Testnet ? 0x6f : 0x00));

	std::vector<uint8_t> SHA256_1 = get_sha_256(Hash160);
	std::vector<uint8_t> SHA256_2 = get_sha_256(SHA256_1);

	if (SHA256_2.empty())
		return std::string();

	Hash160.insert(Hash160.end(), SHA256_2.begin(), SHA256_2.begin() + 4);

	return bin_to_base_58(Hash160);
}

class InvalidAddress {

};

std::vector<uint8_t> decode_from_bitcoin_address(const std::string& Address) {
	// The address length is 25, a single byte testnet prefix and a 4 byte checksum suffix.
	const uint8_t AddressLength = 25;
	const uint8_t CheckSumSuffixLength = 4;
	const uint8_t TestnetPrefixLength = 1;

	std::vector<uint8_t> BinAddress = base_58_to_bin(Address);

	if (BinAddress.size() != AddressLength)
		throw InvalidAddress{  };

	std::vector<uint8_t> CheckSumSuffix(BinAddress.begin() + AddressLength - CheckSumSuffixLength, BinAddress.end());

	BinAddress.erase(BinAddress.begin() + AddressLength - CheckSumSuffixLength, BinAddress.end());

	std::vector<uint8_t> Hash_1 = get_sha_256(BinAddress);

	std::vector<uint8_t> Hash_2 = get_sha_256(Hash_1);

	Hash_2.erase(Hash_2.begin() + CheckSumSuffixLength, Hash_2.end());

	for (size_t counter = 0; counter < CheckSumSuffixLength; ++counter) {
		if (CheckSumSuffix[counter] != Hash_2[counter])
			throw InvalidAddress{};
	}

	BinAddress.erase(BinAddress.begin());

	return BinAddress;
}


std::string encode_to_wif(std::vector<uint8_t> SEC, bool Compressed, bool Testnet) {
	SEC.insert(SEC.begin(), (Testnet ? 0xef : 0x80));

	if (Compressed)
		SEC.push_back(0x01);

	std::vector<uint8_t> SHA256_1 = get_sha_256(SEC);

	std::vector<uint8_t> SHA256_2 = get_sha_256(SHA256_1);


	if (SHA256_2.size() == 0)
		return std::string();

	SEC.insert(SEC.end(), SHA256_2.begin(), SHA256_2.begin() + 4);

	return bin_to_base_58(SEC);
}

std::vector<uint8_t> decode_from_wif(std::string Address) {
	std::vector<uint8_t> BinAddress = base_58_to_bin(Address);

	const uint8_t AddressLength = 38;
	const uint8_t CheckSumSuffixLength = 4;
	const uint8_t TestnetPrefixLength = 1;
	const uint8_t CompressedPrefixLength = 1;

	std::vector<uint8_t> CheckSumSuffix(BinAddress.begin() + AddressLength - CheckSumSuffixLength, BinAddress.end());

	BinAddress.erase(BinAddress.begin() + AddressLength - CheckSumSuffixLength, BinAddress.end());

	std::vector<uint8_t> Hash_1 = get_sha_256(BinAddress);

	std::vector<uint8_t> Hash_2 = get_sha_256(Hash_1);

	Hash_2.erase(Hash_2.begin() + CheckSumSuffixLength, Hash_2.end());

	for (size_t counter = 0; counter < CheckSumSuffixLength; ++counter) {
		if (CheckSumSuffix[counter] != Hash_2[counter])
			throw InvalidAddress{};
	}

	BinAddress.erase(BinAddress.begin());
	BinAddress.pop_back();

	return BinAddress;
}

void adjust_bytes(std::vector<uint8_t>::iterator& start, std::vector<uint8_t>& input, uint32_t serialization_size){
    // We push the bytes to the right of the start iterator downwards so we can make space for the
    // items to be put there now, this allows us to reduce the amount of copying though, 
    // most calls to this in this code already have start positioned at the end, so no moving is
	// performed.

    uint32_t start_index = start - input.begin();

    uint32_t remainder_size = input.size() - start_index;

    input.resize(input.size() + serialization_size);

    // An overlap is possible so we use "copy_backward".
    start = std::copy_backward(input.begin() + start_index, 
    input.begin() + start_index + remainder_size, input.begin() + (input.size() - remainder_size));

	start = input.begin() + start_index;

}