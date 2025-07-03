#include <algorithm>
#include <vector>
#include <iostream>
#include "Compute.h"
#include "../Error/Error.h"
#include "../Serial/Serial.h"

BigNum::ContextType BigNum::context() const{
	static std::shared_ptr<BN_CTX> context(BN_CTX_new(), &BigNum::free_big_number_context);
	return context;
}

BigNum::BigNum(const std::string& number) :number(nullptr, &free_big_number) {
	if (number.size() == 0)
		throw ArithmeticError(ArithmeticError::Type::NUMBER_IS_NULL, "An  std::string of size zero cannot be used for initialization, use the default constructor instead.");

	BIGNUM* BigNumber = BN_new();

	// IMPORTANT: Openssl does not store leading zeros, so when converting to it removes them.
	// Convert string hexadecimal representation of a number to it's binary numeric equivalent.
	BN_hex2bn(&BigNumber, number.c_str());

	this->number = std::move(NumberType(BigNumber, &free_big_number));
}

BigNum::BigNum(NumberType number) :number(nullptr, &free_big_number) {
	if (number.get() == nullptr)
		throw ArithmeticError(ArithmeticError::Type::NUMBER_IS_NULL, "A null value cannot be used for initialization, use the default constructor instead.");

	this->number = std::move(NumberType(BN_dup(number.get()), &free_big_number));
}

BigNum::BigNum(const std::vector<uint8_t>& number) :number(nullptr, &free_big_number) {
	if (number.size() == 0)
		throw ArithmeticError(ArithmeticError::Type::NUMBER_IS_NULL, "An std::vector of size zero cannot be used for initialization, use the default constructor instead.");

	this->number = std::move(NumberType(BN_bin2bn(number.data(), static_cast<int32_t>(number.size()), nullptr), &free_big_number));
}


std::vector<uint8_t> BigNum::to_std_vec() const {
	std::vector<uint8_t> bignum(BN_num_bytes(this->number.get()));

	BN_bn2bin(this->number.get(), bignum.data());

	return bignum;
}

std::vector<uint8_t> BigNum::to_std_vec_16() const {
	std::vector<uint8_t> bignum(to_std_vec());

	while (bignum.size() < sizeof(uint16_t))
		bignum.insert(bignum.begin(), 0x00);

	return bignum;
}

std::vector<uint8_t> BigNum::to_std_vec_32() const {
	std::vector<uint8_t> bignum(to_std_vec());

	while (bignum.size() < sizeof(uint32_t))
		bignum.insert(bignum.begin(), 0x00);

	return bignum;
}

std::vector<uint8_t> BigNum::to_std_vec_64() const {
	std::vector<uint8_t> bignum(to_std_vec());

	while (bignum.size() < sizeof(uint64_t))
		bignum.insert(bignum.begin(), 0x00);

	return bignum;
}

std::string BigNum::to_hex() const {
	
	// IMPORTANT: Openssl does not store leading zeros, so if it was initially set from a string with leading zeros
	// by the time it is making this conversion back the leading zeros would have been removed, this previously caused
	// some debugging issues, so i mention it here.

	char* temp_result = BN_bn2hex(this->number.get());

	std::string result(temp_result);

	OPENSSL_free(temp_result);

	return result;
}

std::string BigNum::to_dec() const {

	// IMPORTANT: Openssl does not store leading zeros, so if it was initially set from a string with leading zeros
	// by the time it is making this conversion back the leading zeros would have been removed, this previously caused
	// some debugging issues, so i mention it here.

	char* temp_result = BN_bn2dec(this->number.get());

	std::string result(temp_result);

	OPENSSL_free(temp_result);

	return result;
}


BigNum::NumberType BigNum::mod_mul(BIGNUM* first, BIGNUM* second, BIGNUM* modulus) const {
	if (BN_is_zero(modulus) == 1)
		throw ArithmeticError(ArithmeticError::Type::DIVISION_BY_ZERO); // Try to catch divsion by zero before openssl.

	NumberType result(BN_new(), &free_big_number);

	BN_mod_mul(result.get(), first, second, modulus, context().get());

	return result;
}

BigNum::NumberType BigNum::mod_exp(BIGNUM* base, BIGNUM* exponent, BIGNUM* modulus) const {
	if (BN_is_zero(modulus) == 1)
		throw ArithmeticError(ArithmeticError::Type::DIVISION_BY_ZERO); // Try to catch divsion by zero before openssl.

	NumberType result(BN_new(), &free_big_number);

	BN_mod_exp(result.get(), base, exponent, modulus, context().get());
	return result;
}

BigNum::NumberType BigNum::exp(BIGNUM* first, BIGNUM* second) const {
		
	NumberType result(BN_new(), &free_big_number);
	BN_exp(result.get(), first, second, context().get());

	return result;
}

BigNum::NumberType BigNum::mod(BIGNUM* first, BIGNUM* second) const {
	if (BN_is_zero(second) == 1)
		throw ArithmeticError(ArithmeticError::Type::DIVISION_BY_ZERO); // Try to catch divsion by zero before openssl.

	NumberType result(BN_new(), &free_big_number);

	BN_nnmod(result.get(), first, second, context().get());

	return result;
}

BigNum::NumberType BigNum::mul(BIGNUM* first, BIGNUM* second) const {
	NumberType result(BN_new(), &free_big_number);

	BN_mul(result.get(), first, second, context().get());

	return result;
}

BigNum::NumberType BigNum::div(BIGNUM* first, BIGNUM* second) const {
	if (BN_is_zero(second) == 1)
		throw ArithmeticError(ArithmeticError::Type::DIVISION_BY_ZERO); // Try to catch divsion by zero before openssl.

	NumberType result(BN_new(), &free_big_number);

	BN_div(result.get(), nullptr, first, second, context().get());

	return result;
}

BigNum::NumberType BigNum::add(BIGNUM* first, BIGNUM* second) const {
	NumberType result(BN_new(), &free_big_number);

	BN_add(result.get(), first, second);

	return result;
}

BigNum::NumberType BigNum::sub(BIGNUM* first, BIGNUM* second) const {
	NumberType result(BN_new(), &free_big_number);

	BN_sub(result.get(), first, second);

	return result;
}