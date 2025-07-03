#pragma once
#include <cmath>
#include <vector>
#include <string>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <memory>
#include <algorithm>
#include <concepts>
#include "../Serial/Serial.h"

class BigNum {
public:

	// Context deleter.
	void static free_big_number_context(BN_CTX* NumberContext) {
		BN_CTX_free(NumberContext);
	}

	// Number representation deleter.
	void static free_big_number(BIGNUM* Number) {
		BN_free(Number);
	}

	typedef decltype(&free_big_number) NumberDeleter;

	typedef decltype(&free_big_number_context) ContextDeleter;

	typedef std::unique_ptr<BIGNUM, NumberDeleter> NumberType;

	typedef std::shared_ptr<BN_CTX> ContextType;

	template <std::integral T>
	BigNum(T number) :number(nullptr, &free_big_number) {

		bool negative = number < 0;

		if (negative){
			number = -number;
		}

		std::vector<uint8_t> vector_bytes(sizeof(number));
		auto vector_bytes_iterator = vector_bytes.begin();

		// Write the bytes in little endian.
		write_int_as_little_endian_bytes(number, vector_bytes_iterator, vector_bytes);

		std::reverse(vector_bytes.begin(), vector_bytes.end()); // The "write_int_as_little_endian_bytes" function extracts the bytes in little-endian
																// but Openssl uses big-endian.

		this->number = std::move(NumberType(BN_bin2bn(vector_bytes.data(), 
		static_cast<int32_t>(vector_bytes.size()), nullptr), &free_big_number));

		// Set negative if so.
		BN_set_negative(this->number.get(), negative);
}

	BigNum(const std::string& Number);

	BigNum(NumberType Number);

	BigNum(const std::vector<uint8_t>& Number);

	BigNum(const BigNum& Element) :number(BN_dup(Element.number.get()), &free_big_number) {
	}

	BigNum() :number(BN_new(), &free_big_number) {
	}

	~BigNum() {
	}

	BigNum& operator=(const BigNum& Element) {
		BN_copy(number.get(), Element.number.get());
		return *this;
	}

	bool operator<(const BigNum& OtherElement) const {
		return (BN_cmp(number.get(), OtherElement.number.get()) == -1);
	}

	bool operator>(const BigNum& OtherElement) const {
		return (BN_cmp(number.get(), OtherElement.number.get()) == 1);
	}

	bool operator==(const BigNum& OtherElement) const {
		return (BN_cmp(number.get(), OtherElement.number.get()) == 0);
	}

	bool operator<=(const BigNum& OtherElement) const {
		return (*this < OtherElement || *this == OtherElement);
	}

	bool operator>=(const BigNum& OtherElement) const {
		return (*this > OtherElement || *this == OtherElement);
	}

	bool operator!=(const BigNum& OtherElement) const {
		return !(OtherElement == *this);
	}

	BigNum operator+(const BigNum& OtherElement) const {
		return BigNum(add(number.get(), OtherElement.number.get()));
	}

	BigNum operator-(const BigNum& OtherElement) const {
		return BigNum(sub(number.get(), OtherElement.number.get()));
	}

	BigNum operator-() const {
		return BigNum(0) - *this;
	}

	BigNum operator*(BigNum Element) const {
		return BigNum(mul(number.get(), Element.number.get()));
	}

	BigNum operator/(BigNum Element) const {
		return BigNum(div(number.get(), Element.number.get()));
	}

	BigNum operator^(BigNum Element) const {
		return BigNum(exp(number.get(), Element.number.get()));
	}

	// Calculates the result of exponentiating number to element and taking the modulo to modulus
	// It is usally much faster that performing them as separate operations thanks to algorithms like
	// that of montegmorey.
	BigNum mod_exp(BigNum Element, BigNum Modulus) const {
		return BigNum(mod_exp(number.get(), Element.number.get(), Modulus.number.get()));
	}

	// Calculates the result of multiplying number to element and taking the modulo to modulus.
	BigNum mod_mul(BigNum Element, BigNum Modulus) const {
		return BigNum(mod_mul(number.get(), Element.number.get(), Modulus.number.get()));
	}

	BigNum operator%(BigNum Element) const {
		return BigNum(mod(number.get(), Element.number.get()));
	}

	void negate() {
		BN_set_negative(number.get(), BN_is_negative(number.get()) == 0 ? 1 : 0);
	}

	void set_absolute() { 
		BN_set_negative(number.get(), 0);
	}

	// Checks if it is signed and can also be stored in C++ largest primitive type.
	bool is_signed_small() const {
		if (BN_num_bytes(number.get()) <= 8) { // Check if it can be stored in C++'s primitive types.
			// Checks if it is within the bounds of the largest primitive type that C++ offers
			if (*this <= 0)
				return (*this >= std::numeric_limits<int64_t>::min()); 
			else {
				return (*this <= std::numeric_limits<int64_t>::max());
			}
		}

		return false;
	}

	// Checks if it is unsigned and can also be stored in C++ largest primitive type.
	bool is_unsigned_small() const {
		return BN_num_bytes(number.get()) <= 8 && // Check if it can be stored in C++'s primitive types.
			// Checks if it is within the bounds of the largest primitive type that C++ offers
			((*this > std::numeric_limits<uint64_t>::min()) || (*this == std::numeric_limits<uint64_t>::min())) &&
			((*this < std::numeric_limits<uint64_t>::max()) || (*this == std::numeric_limits<uint64_t>::max()));
	}

	// Get the signed number equivalent, the function is not defined if the value has a byte size greater than 8
	// but Openssl probably truncates the leading bytes.
	int64_t get_signed_small() const {
		uint64_t Result = BN_get_word(number.get());
		return (*this < 0 ? -static_cast<int64_t>(Result) : static_cast<int64_t>(Result));
	}

	// Get the unsigned number equivalent, the function is not defined if the value has a byte size greater than 8
	// but Openssl probably truncates the leading bytes.
	int64_t get_unsigned_small() const {
		return BN_get_word(number.get());
	}

	uint64_t byte_count() const {
		return BN_num_bytes(number.get());
	}

	std::vector<uint8_t> to_std_vec() const;

	std::vector<uint8_t> to_std_vec_16() const;

	std::vector<uint8_t> to_std_vec_32() const;

	std::vector<uint8_t> to_std_vec_64() const;

	std::string to_hex() const;

	std::string to_dec() const;

private:

	NumberType mod_mul(BIGNUM*, BIGNUM*, BIGNUM*) const;

	NumberType mod_exp(BIGNUM*, BIGNUM*, BIGNUM*) const;

	NumberType exp(BIGNUM*, BIGNUM*) const;

	NumberType mod(BIGNUM*, BIGNUM*) const;

	NumberType mul(BIGNUM*, BIGNUM*) const;

	NumberType div(BIGNUM*, BIGNUM*) const;

	NumberType add(BIGNUM*, BIGNUM*) const;

	NumberType sub(BIGNUM*, BIGNUM*) const;

	// The context performs most of the calculations that the numbers perform, 
	// there is no intermediary state(at least for no operation that i know of that is supported) so it safe to
	// share the context among all instances in a single threaded program.
	ContextType context() const; 

	NumberType number; // The number.
};
