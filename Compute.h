#pragma once
#include <cmath>
#include <vector>
#include <string>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <memory>

class BigNum {
public:

	class NumberIsNull {
	public:
		NumberIsNull(std::string Message = "What are you doing?") :Message(Message) {}
		std::string Message;
	};

	class DivisionByZero {
	public:
		DivisionByZero(std::string Message = "What are you doing?") :Message() {}
		std::string Message;
	};

	void static FreeBigNumberContext(BN_CTX* NumberContext) {
		BN_CTX_free(NumberContext);
	}

	void static FreeBigNumber(BIGNUM* Number) {
		BN_free(Number);
	}

	typedef decltype(&FreeBigNumber) NumberDeleter;

	typedef decltype(&FreeBigNumberContext) ContextDeleter;

	typedef std::unique_ptr<BIGNUM, NumberDeleter> NumberType;

	typedef std::shared_ptr<BN_CTX> ContextType;

	BigNum(int32_t Number);

	BigNum(int64_t Number);

	BigNum(uint32_t Number);

	BigNum(uint64_t Number);

	BigNum(const std::string& Number);

	BigNum(NumberType Number);

	BigNum(const std::vector<uint8_t>& Number);

	BigNum(const BigNum& Element) :_Number(BN_dup(Element._Number.get()), &FreeBigNumber) {
	}

	BigNum() :_Number(BN_new(), &FreeBigNumber) {
	}

	~BigNum() {
	}

	BigNum& operator=(const BigNum& Element) {
		BN_copy(_Number.get(), Element._Number.get());
		return *this;
	}

	bool operator<(const BigNum& OtherElement) const {
		return (BN_cmp(_Number.get(), OtherElement._Number.get()) == -1);
	}

	bool operator>(const BigNum& OtherElement) const {
		return (BN_cmp(_Number.get(), OtherElement._Number.get()) == 1);
	}

	bool operator==(const BigNum& OtherElement) const {
		return (BN_cmp(_Number.get(), OtherElement._Number.get()) == 0);
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
		return BigNum(Add(_Number.get(), OtherElement._Number.get()));
	}

	BigNum operator-(const BigNum& OtherElement) const {
		return BigNum(Sub(_Number.get(), OtherElement._Number.get()));
	}

	BigNum operator-() const {
		return BigNum(0) - *this;
	}

	BigNum operator*(BigNum Element) const {
		return BigNum(Mul(_Number.get(), Element._Number.get()));
	}

	BigNum operator/(BigNum Element) const {
		return BigNum(Div(_Number.get(), Element._Number.get()));
	}

	BigNum operator^(BigNum Element) const {
		return BigNum(Exp(_Number.get(), Element._Number.get()));
	}

	BigNum ModExp(BigNum Element, BigNum Modulus) const {
		return BigNum(ModExp(_Number.get(), Element._Number.get(), Modulus._Number.get()));
	}

	BigNum ModMul(BigNum Element, BigNum Modulus) const {
		return BigNum(ModMul(_Number.get(), Element._Number.get(), Modulus._Number.get()));
	}

	BigNum operator%(BigNum Element) const {
		return BigNum(Mod(_Number.get(), Element._Number.get()));
	}

	void Negate() { // Non-const.
		BN_set_negative(_Number.get(), BN_is_negative(_Number.get()) == 0 ? 1 : 0);
	}

	void Absolute() { // Non-const.
		BN_set_negative(_Number.get(), 0);
	}

	bool IsSignedSmall() const {
		if (BN_num_bytes(_Number.get()) <= 8) {
			if (*this <= 0)
				return (*this >= std::numeric_limits<int64_t>::min());
			else {
				return (*this <= std::numeric_limits<int64_t>::max());
			}
		}
	}

	bool IsUnSignedSmall() const {
		return BN_num_bytes(_Number.get()) <= 8 &&
			((*this > std::numeric_limits<uint64_t>::min()) || (*this == std::numeric_limits<uint64_t>::min())) &&
			((*this < std::numeric_limits<uint64_t>::max()) || (*this == std::numeric_limits<uint64_t>::max()));
	}

	int64_t GetSignedSmall() const {
		uint64_t Result = BN_get_word(_Number.get());
		return (*this < 0 ? -static_cast<int64_t>(Result) : static_cast<int64_t>(Result));
	}

	int64_t GetUnsignedSmall() const {
		return BN_get_word(_Number.get());
	}

	uint64_t ByteCount() const {
		return BN_num_bytes(_Number.get());
	}

	std::vector<uint8_t> ToStdVec() const;

	std::vector<uint8_t> ToStdVec_16() const;

	std::vector<uint8_t> ToStdVec_32() const;

	std::vector<uint8_t> ToStdVec_64() const;

	std::string ToHex() const;

	std::string ToDec() const;

private:

	NumberType ModMul(BIGNUM* First, BIGNUM* Second, BIGNUM* Modulus) const;

	NumberType ModExp(BIGNUM* Base, BIGNUM* Exponent, BIGNUM* Modulus) const;

	NumberType Exp(BIGNUM* First, BIGNUM* Second) const;

	NumberType Mod(BIGNUM* First, BIGNUM* Second) const;

	NumberType Mul(BIGNUM* First, BIGNUM* Second) const;

	NumberType Div(BIGNUM* First, BIGNUM* Second) const;

	NumberType Add(BIGNUM* First, BIGNUM* Second) const;

	NumberType Sub(BIGNUM* First, BIGNUM* Second) const;

	NumberType _Number;
	static ContextType _Context;
};
