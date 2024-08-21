#include "Compute.h"

std::shared_ptr<BN_CTX> BigNum::_Context(BN_CTX_new(), &BigNum::FreeBigNumberContext);


BigNum::BigNum(int32_t Number) :_Number(nullptr, &FreeBigNumber) {
	bool Negative = Number < 0;
	if (Negative)
		Number = -Number;
	std::vector<uint8_t> Number_(sizeof(int32_t));
	std::copy_n((uint8_t*)&Number, sizeof(int32_t), Number_.data());

	std::reverse(Number_.begin(), Number_.end());

	_Number = std::move(NumberType(BN_bin2bn(Number_.data(), static_cast<int32_t>(Number_.size()), nullptr), &FreeBigNumber));
	BN_set_negative(_Number.get(), Negative);
}

BigNum::BigNum(int64_t Number) :_Number(nullptr, &FreeBigNumber) {
	bool Negative = Number < 0;
	if (Negative)
		Number = -Number;
	std::vector<uint8_t> Number_(sizeof(int64_t));
	std::copy_n((uint8_t*)&Number, sizeof(int64_t), Number_.data());

	std::reverse(Number_.begin(), Number_.end());

	_Number = std::move(NumberType(BN_bin2bn(Number_.data(), static_cast<int32_t>(Number_.size()), nullptr), &FreeBigNumber));
	BN_set_negative(_Number.get(), Negative);
}

BigNum::BigNum(uint32_t Number) :_Number(nullptr, &FreeBigNumber) {
	std::vector<uint8_t> Number_(sizeof(uint32_t));
	std::copy_n((uint8_t*)&Number, sizeof(uint32_t), Number_.data());

	std::reverse(Number_.begin(), Number_.end());

	_Number = std::move(NumberType(BN_bin2bn(Number_.data(), static_cast<int32_t>(Number_.size()), nullptr), &FreeBigNumber));
}

BigNum::BigNum(uint64_t Number) :_Number(nullptr, &FreeBigNumber) {
	std::vector<uint8_t> Number_(sizeof(uint64_t));
	std::copy_n((uint8_t*)&Number, sizeof(uint64_t), Number_.data());

	std::reverse(Number_.begin(), Number_.end());

	_Number = std::move(NumberType(BN_bin2bn(Number_.data(), static_cast<int32_t>(Number_.size()), nullptr), &FreeBigNumber));
}

BigNum::BigNum(const std::string& Number) :_Number(nullptr, &FreeBigNumber) {
	if (Number.size() == 0)
		throw NumberIsNull("An std::string of size zero cannot be used for initialization, use the default constructor instead.");

	BIGNUM* BigNumber = BN_new();

	BN_hex2bn(&BigNumber, Number.c_str());

	_Number = std::move(NumberType(BigNumber, &FreeBigNumber));
}

BigNum::BigNum(NumberType Number) :_Number(nullptr, &FreeBigNumber) {
	if (Number.get() == nullptr)
		throw NumberIsNull("A null value cannot be used for initialization, use the default constructor instead.");

	_Number = std::move(NumberType(BN_dup(Number.get()), &FreeBigNumber));
}

BigNum::BigNum(const std::vector<uint8_t>& Number) :_Number(nullptr, &FreeBigNumber) {
	if (Number.size() == 0)
		throw NumberIsNull("An std::vector of size zero cannot be used for initialization, use the default constructor instead.");

	_Number = std::move(NumberType(BN_bin2bn(Number.data(), static_cast<int32_t>(Number.size()), nullptr), &FreeBigNumber));
}


std::vector<uint8_t> BigNum::ToStdVec() const {
	std::vector<uint8_t> BigNum_(BN_num_bytes(_Number.get()));

	BN_bn2bin(_Number.get(), BigNum_.data());

	return BigNum_;
}

std::vector<uint8_t> BigNum::ToStdVec_16() const {
	std::vector<uint8_t> BigNum_(ToStdVec());

	while (BigNum_.size() < sizeof(uint16_t))
		BigNum_.insert(BigNum_.begin(), 0x00);

	return BigNum_;
}

std::vector<uint8_t> BigNum::ToStdVec_32() const {
	std::vector<uint8_t> BigNum_(ToStdVec());

	while (BigNum_.size() < sizeof(uint32_t))
		BigNum_.insert(BigNum_.begin(), 0x00);

	return BigNum_;
}

std::vector<uint8_t> BigNum::ToStdVec_64() const {
	std::vector<uint8_t> BigNum_(ToStdVec());

	while (BigNum_.size() < sizeof(uint64_t))
		BigNum_.insert(BigNum_.begin(), 0x00);

	return BigNum_;
}

std::string BigNum::ToHex() const {
	std::string BigNum_;

	BigNum_ = BN_bn2hex(_Number.get());

	return BigNum_;
}

std::string BigNum::ToDec() const {
	std::string BigNum_;

	BigNum_ = BN_bn2dec(_Number.get());

	return BigNum_;
}


BigNum::NumberType BigNum::ModMul(BIGNUM* First, BIGNUM* Second, BIGNUM* Modulus) const {
	if (BN_is_zero(Modulus) == 1)
		throw DivisionByZero();

	NumberType Result(BN_new(), &FreeBigNumber);

	BN_mod_mul(Result.get(), First, Second, Modulus, _Context.get());
	return std::move(Result);
}

BigNum::NumberType BigNum::ModExp(BIGNUM* Base, BIGNUM* Exponent, BIGNUM* Modulus) const {
	if (BN_is_zero(Modulus) == 1)
		throw DivisionByZero();

	NumberType Result(BN_new(), &FreeBigNumber);

	BN_mod_exp(Result.get(), Base, Exponent, Modulus, _Context.get());
	return std::move(Result);
}

BigNum::NumberType BigNum::Exp(BIGNUM* First, BIGNUM* Second) const {
	NumberType Result(BN_new(), &FreeBigNumber);

	BN_exp(Result.get(), First, Second, _Context.get());

	return std::move(Result);
}

BigNum::NumberType BigNum::Mod(BIGNUM* First, BIGNUM* Second) const {
	if (BN_is_zero(Second) == 1)
		throw DivisionByZero();

	NumberType Result(BN_new(), &FreeBigNumber);

	BN_nnmod(Result.get(), First, Second, _Context.get());

	return std::move(Result);
}

BigNum::NumberType BigNum::Mul(BIGNUM* First, BIGNUM* Second) const {
	NumberType Result(BN_new(), &FreeBigNumber);

	BN_mul(Result.get(), First, Second, _Context.get());

	return std::move(Result);
}

BigNum::NumberType BigNum::Div(BIGNUM* First, BIGNUM* Second) const {
	if (BN_is_zero(Second) == 1)
		throw DivisionByZero();

	NumberType Result(BN_new(), &FreeBigNumber);

	BN_div(Result.get(), nullptr, First, Second, _Context.get());

	return std::move(Result);
}

BigNum::NumberType BigNum::Add(BIGNUM* First, BIGNUM* Second) const {
	NumberType Result(BN_new(), &FreeBigNumber);

	BN_add(Result.get(), First, Second);

	return std::move(Result);
}

BigNum::NumberType BigNum::Sub(BIGNUM* First, BIGNUM* Second) const {
	NumberType Result(BN_new(), &FreeBigNumber);

	BN_sub(Result.get(), First, Second);

	return std::move(Result);
}