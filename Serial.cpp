#pragma once
#include <iomanip>
#include <iostream>
#include "Crypt.h"
#include "Debug functions.h"
#include <unordered_map>

std::string BinToBase58(const std::vector<uint8_t>& Vec) {
	std::string Base58_Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	BigNum Bin(Vec);

	std::string Base58Result;

	while (Bin > 0) {
		Base58Result.push_back(Base58_Alphabet[(Bin % 58).GetUnsignedSmall()]);
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

std::vector<uint8_t> Base58ToBin(std::string Hex) {
	std::string Base58_Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	std::unordered_map<uint8_t, uint8_t> LetterToNumber;

	for (size_t Counter = 0; Counter < Base58_Alphabet.size(); Counter++) {
		LetterToNumber.emplace(Base58_Alphabet[Counter], Counter);
	}

	BigNum Number = 0;

	//std::reverse(Hex.begin(), Hex.end());

	for (size_t Counter = 0; Counter < Hex.size(); Counter++) {
		Number = (Number * 58) + LetterToNumber[Hex[Counter]];
	}

	std::vector<uint8_t> Result = Number.ToStdVec();

	std::string::const_iterator Iterator = Hex.begin();

	while (*Iterator == Base58_Alphabet[0]) {
		Result.insert(Result.begin(), 0x00);
		Iterator++;
	}

	return Result;
}
std::string EncodeToBitcoinAddress(const std::vector<uint8_t>& SEC, bool Testnet) {

	// Step 1: Get HASH160 of the public key
	std::vector<uint8_t> Hash160 = GetHASH160(SEC);

	if (Hash160.empty())
		return std::string();

	// Step 2: Add version byte
	Hash160.insert(Hash160.begin(), (Testnet ? 0x6f : 0x00)); // Testnet: 0x6f, Mainnet: 0x00

	// Step 3: Calculate checksum
	std::vector<uint8_t> SHA256_1 = GetSHA256(Hash160);
	std::vector<uint8_t> SHA256_2 = GetSHA256(SHA256_1);

	if (SHA256_2.empty())
		return std::string();

	// Step 4: Append the first 4 bytes of the second SHA-256 hash as a checksum
	Hash160.insert(Hash160.end(), SHA256_2.begin(), SHA256_2.begin() + 4);

	std::cout << "Address before:- ";
	HexDump(Hash160.begin(), Hash160.size());

	// Step 5: Encode the result in Base58
	return BinToBase58(Hash160);
}

class InvalidAddress {

};

std::vector<uint8_t> DecodeFromBitcoinAddress(const std::string& Address) {
	// The address length is 25, a single byte testnet prefix and a 4 byte checksum suffix.
	const uint8_t AddressLength = 25;
	const uint8_t CheckSumSuffixLength = 4;
	const uint8_t TestnetPrefixLength = 1;

	std::vector<uint8_t> BinAddress = Base58ToBin(Address);

	if (BinAddress.size() != AddressLength)
		throw InvalidAddress{  };

	std::vector<uint8_t> CheckSumSuffix(BinAddress.begin() + AddressLength - CheckSumSuffixLength, BinAddress.end());

	BinAddress.erase(BinAddress.begin() + AddressLength - CheckSumSuffixLength, BinAddress.end());

	std::vector<uint8_t> Hash_1 = GetSHA256(BinAddress);

	std::vector<uint8_t> Hash_2 = GetSHA256(Hash_1);

	Hash_2.erase(Hash_2.begin() + CheckSumSuffixLength, Hash_2.end());

	for (size_t Counter = 0; Counter < CheckSumSuffixLength; Counter++) {
		if (CheckSumSuffix[Counter] != Hash_2[Counter])
			throw InvalidAddress{};
	}

	BinAddress.erase(BinAddress.begin());

	return BinAddress;
}


std::string EncodeToWIF(std::vector<uint8_t> SEC, bool Compressed, bool Testnet) {
	SEC.insert(SEC.begin(), (Testnet ? 0xef : 0x80));

	if (Compressed)
		SEC.push_back(0x01);

	std::vector<uint8_t> SHA256_1 = GetSHA256(SEC);

	std::vector<uint8_t> SHA256_2 = GetSHA256(SHA256_1);


	if (SHA256_2.size() == 0)
		return std::string();

	SEC.insert(SEC.end(), SHA256_2.begin(), SHA256_2.begin() + 4);

	return BinToBase58(SEC);
}

std::vector<uint8_t> DecodeFromWIF(std::string Address) {
	std::vector<uint8_t> BinAddress = Base58ToBin(Address);

	const uint8_t AddressLength = 38;
	const uint8_t CheckSumSuffixLength = 4;
	const uint8_t TestnetPrefixLength = 1;
	const uint8_t CompressedPrefixLength = 1;

	std::vector<uint8_t> CheckSumSuffix(BinAddress.begin() + AddressLength - CheckSumSuffixLength, BinAddress.end());

	BinAddress.erase(BinAddress.begin() + AddressLength - CheckSumSuffixLength, BinAddress.end());

	std::vector<uint8_t> Hash_1 = GetSHA256(BinAddress);

	std::vector<uint8_t> Hash_2 = GetSHA256(Hash_1);

	Hash_2.erase(Hash_2.begin() + CheckSumSuffixLength, Hash_2.end());

	for (size_t Counter = 0; Counter < CheckSumSuffixLength; Counter++) {
		if (CheckSumSuffix[Counter] != Hash_2[Counter])
			throw InvalidAddress{};
	}

	BinAddress.erase(BinAddress.begin());
	BinAddress.pop_back();

	return BinAddress;
}
