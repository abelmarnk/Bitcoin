#pragma once
#include "Crypt.h"
#include <unordered_map>

std::string BinToBase58(const std::vector<uint8_t>& Vec);

std::vector<uint8_t> Base58ToBin(std::string Hex);
std::string EncodeToBitcoinAddress(const std::vector<uint8_t>& SEC, bool Testnet);

class InvalidAddress {

};

std::vector<uint8_t> DecodeFromBitcoinAddress(const std::string& Address);


std::string EncodeToWIF(std::vector<uint8_t> SEC, bool Compressed, bool Testnet);

std::vector<uint8_t> DecodeFromWIF(std::string Address);
