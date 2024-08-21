#include "Crypt.h"

BigFieldElement BigFieldElement::operator^(BigNum Exponent) const {
	if (Exponent < 0) {
		Exponent.Absolute();
		return  (*this ^ (_Prime - 2)) ^ Exponent;
	}
	else {
		return BigFieldElement(_Number.ModExp(Exponent, _Prime), _Prime);
	}
}

BigFieldElement BigFieldElement::Sqrt() const {
	if ((_Prime + 1) % 4 != 0)
		throw UndefinedOperation("The Prime is not congruent to 3 modulo 4.");

	return *this ^ ((_Prime + 1) / 4);
}

std::vector<uint8_t> Signature::DERtoStdVec() {
	std::vector<uint8_t> Bin;

	Bin.push_back(0x30);

	auto R = _R.ToStdVec();
	auto S = _S.ToStdVec();

	Bin.push_back(0x02);

	Bin.push_back(R.size() + static_cast<uint64_t>((*(R.begin()) >= 0x80 ? 1 : 0)));
	if (*(R.begin()) >= 0x80)
		Bin.push_back(0x00);

	uint64_t Position = Bin.size();

	Bin.resize(Bin.size() + R.size());
	std::copy(R.begin(), R.end(), Bin.begin() + Position);

	Bin.push_back(0x02);

	Bin.push_back(S.size() + static_cast<uint64_t>((*(S.begin()) >= 0x80 ? 1 : 0)));
	if (*(S.begin()) >= 0x80)
		Bin.push_back(0x00);

	Position = Bin.size();

	Bin.resize(Bin.size() + S.size());
	std::copy(S.begin(), S.end(), Bin.begin() + Position);

	return Bin;
}

void Signature::StdVecToDER(const std::vector<uint8_t>& Vector) {
	std::vector<uint8_t> R_;
	std::vector<uint8_t> S_;
	auto Iterator = Vector.begin();

	if (*Iterator != 0x30)
		throw InvalidVector{};
	Iterator++;

	if (*Iterator != 0x02)
		throw InvalidVector{};
	Iterator++;

	size_t _RSize = *Iterator;;

	Iterator++;

	if (*Iterator == 0x00) {
		Iterator++;
		_RSize--;
	}

	R_.resize(_RSize);

	std::copy(Iterator, Iterator + _RSize, R_.begin());

	Iterator += _RSize;


	if (*Iterator != 0x02)
		throw InvalidVector{};
	Iterator++;

	size_t S_Size_ = *Iterator;;

	Iterator++;

	if (*Iterator == 0x00) {
		Iterator++;
		S_Size_--;
	}

	S_.resize(S_Size_);

	std::copy(Iterator, Iterator + S_Size_, S_.begin());

	Iterator += S_Size_;

	_R = R_;
	_S = S_;
}

std::vector<uint8_t> Digest(const std::vector<uint8_t>& Message, const std::string& Digest) {
	std::unique_ptr<EVP_MD, decltype(&FreeDigest)> DigestAlgorithm(EVP_MD_fetch(nullptr, Digest.c_str(), nullptr), &FreeDigest);
	std::unique_ptr<EVP_MD_CTX, decltype(&FreeContext)> DigestContext(EVP_MD_CTX_new(), &FreeContext);

	if (DigestAlgorithm == nullptr) {
		return std::vector<uint8_t>();
	}

	if (DigestContext == nullptr) {
		EVP_MD_free(DigestAlgorithm.get());
		return std::vector<uint8_t>();
	}

	EVP_DigestInit_ex2(DigestContext.get(), DigestAlgorithm.get(), nullptr);

	const std::uint64_t BatchSize = EVP_MD_block_size(DigestAlgorithm.get());
	std::uint64_t InputUsed = 0;

	while (InputUsed < Message.size()) {
		EVP_DigestUpdate(DigestContext.get(), Message.data() + InputUsed, std::min(BatchSize, Message.size() - InputUsed));
		InputUsed += std::min(BatchSize, Message.size() - InputUsed);
	}

	std::vector<uint8_t> Result(EVP_MD_CTX_get_size(DigestContext.get()), '\0');
	std::uint32_t ResultSize = 0;

	EVP_DigestFinal_ex(DigestContext.get(), (uint8_t*)Result.data(), &ResultSize);

	Result.resize(ResultSize);

	return Result;
}

std::vector<uint8_t> GetHASH160(const std::vector<uint8_t>& Message) {
	// Hash160 is gotten by SHA256 and then RIPEMD160.
	auto SHA256 = GetSHA256(Message);
	if (SHA256.size() == 0)
		return std::vector<uint8_t>();

	auto Hash160 = GetRIPEMD160(SHA256);
	if (Hash160.size() == 0)
		return std::vector<uint8_t>();

	return Hash160;
}

BigPoint::BigPoint(const BigPoint& P) {
	if (P._Infinity) {
		_a = (P._a);
		_b = (P._b);
		_Infinity = true;
	}
	else
	{
		_x = (P._x);
		_y = (P._y);
		_a = (P._a);
		_b = (P._b);
		_Infinity = false;

		if ((_y * _y) != ((_x * _x * _x) + (_a * _x) + _b))
			throw InvalidPoint();
	}
}

BigPoint& BigPoint::operator=(const BigPoint& P) {
	if (P._Infinity) {
		_a = (P._a);
		_b = (P._b);
		_Infinity = true;
	}
	else
	{
		_x = (P._x);
		_y = (P._y);
		_a = (P._a);
		_b = (P._b);
		_Infinity = false;

		if ((_y * _y) != ((_x * _x * _x) + (_a * _x) + _b))
			throw InvalidPoint();
	}
	return *this;
}

BigPoint BigPoint::operator+(const BigPoint& OtherPoint) const {
	if (!(OtherPoint._a == _a && OtherPoint._b == _b))
		throw CurveMismatch();

	if (_Infinity)
		return OtherPoint;

	if (OtherPoint._Infinity)
		return *this;

	if (OtherPoint._x == _x && _y == (BigFieldElement(0, OtherPoint._y._Prime) - OtherPoint._y))
		return BigPoint(_a, _b);

	if (OtherPoint._x == _x && (OtherPoint._y == _y) && (_y == BigFieldElement(0, _y._Prime)))
		return BigPoint(_a, _b);

	BigFieldElement Slope_;

	if (OtherPoint._x != _x)
		Slope_ = (OtherPoint._y - _y) / (OtherPoint._x - _x);
	else {
		Slope_ = ((_x * _x * 3) + _a) / (_y * 2);
	}

	BigFieldElement X_ = ((Slope_ * Slope_) - _x) - OtherPoint._x;

	BigFieldElement Y_ = (Slope_ * (_x - X_)) - _y;

	return BigPoint(_a, _b, X_, Y_);
}

BigPoint BigPoint::operator*(BigNum Scalar) const {
	BigPoint Result(_a, _b);  // Point at infinity
	BigPoint TempPoint = *this;

	while (Scalar > 0) {
		if (Scalar % 2 == 1) {
			Result = Result + TempPoint;
		}
		TempPoint = TempPoint + TempPoint;
		Scalar = Scalar / 2;
	}

	return Result;
}

std::string BigPoint::UncompressedSecToHex() const {
	const uint8_t ByteCount = 64;

	if (_Infinity)
		throw InvalidPoint();

	std::string Sec(ByteCount * 2 + 2, '\0');
	std::string::iterator Sec_Iterator = Sec.begin();
	*Sec_Iterator = '0';
	Sec_Iterator++;
	*Sec_Iterator = '4';
	Sec_Iterator++;

	auto Sec_X = _x._Number.ToHex();
	uint8_t Counter = 0;
	while (Sec_X.size() + Counter < ByteCount) {
		*Sec_Iterator = '0';
		Sec_Iterator++;
		*Sec_Iterator = '0';
		Sec_Iterator++;
		Counter++;
	}

	Sec_Iterator = std::copy(Sec_X.begin(), Sec_X.end(), Sec_Iterator);

	auto Sec_Y = _y._Number.ToHex();
	Counter = 0;
	while (Sec_Y.size() + Counter < ByteCount) {
		*Sec_Iterator = '0';
		Sec_Iterator++;
		*Sec_Iterator = '0';
		Sec_Iterator++;
		Counter++;
	}

	Sec_Iterator = std::copy(Sec_Y.begin(), Sec_Y.end(), Sec_Iterator);

	return Sec;
}

std::string BigPoint::CompressedSecToHex() const {
	const uint8_t ByteCount = 64;

	if (_Infinity)
		throw InvalidPoint();

	std::string Sec(ByteCount + 2, '\0');
	std::string::iterator Sec_Iterator = Sec.begin();

	*Sec_Iterator = '0';
	Sec_Iterator++;
	*Sec_Iterator = ((_y._Number % 2 == 0) ? '2' : '3'); //Parity.
	Sec_Iterator++;

	auto Sec_X = _x._Number.ToHex();

	uint8_t Counter = 0;
	while (Sec_X.size() + Counter < ByteCount) {
		*Sec_Iterator = '0';
		Sec_Iterator++;
		*Sec_Iterator = '0';
		Sec_Iterator++;
		Counter++;
	}

	std::copy(Sec_X.begin(), Sec_X.end(), Sec_Iterator);

	return Sec;
}

void BigPoint::UncompressedSecFromStdVec(const std::vector<uint8_t>& Sec) {
	const uint8_t ByteCount = 32;

	std::pair<std::vector<uint8_t>, std::vector<uint8_t>> Sec_X_Y;

	std::vector<uint8_t>::const_iterator Sec_Iterator = Sec.cbegin();
	if (*Sec_Iterator != 0x04)
		throw InvalidPoint();

	Sec_Iterator++; // Skip past the prefix.

	Sec_X_Y.first.resize(ByteCount);
	std::copy_n(Sec_Iterator, ByteCount, Sec_X_Y.first.begin());
	Sec_Iterator += ByteCount;
	_x = BigFieldElement(Sec_X_Y.first, _a._Prime);

	Sec_X_Y.second.resize(ByteCount);
	std::copy_n(Sec_Iterator, ByteCount, Sec_X_Y.second.begin());
	_y = BigFieldElement(Sec_X_Y.second, _a._Prime);

	if (_y * _y != ((_x * _x * _x) + (_a * _x) + _b)) // Check for point validity.
		throw InvalidPoint();

	_Infinity = false;
}

void  BigPoint::CompressedSecFromStdVec(std::vector<uint8_t> Sec) {
	const uint8_t Parity = *(Sec.begin()); //Parity.

	if (Parity != 0x02 && Parity != 0x03)
		throw InvalidPoint();

	Sec.erase(Sec.begin()); //Remove the Parity indicator.

	_x = BigFieldElement(Sec, _a._Prime);

	_y = ((_x * _x * _x) + (_a * _x) + _b).Sqrt();

	if (Parity == 0x02) {
		if (_y._Number % 2 == 1)
			_y._Number = _y._Prime - _y._Number;
	}
	else {
		if (_y._Number % 2 == 0)
			_y._Number = _y._Prime - _y._Number;
	}

	if (_y * _y != ((_x * _x * _x) + (_a * _x) + _b)) // Check for point validity.
		throw InvalidPoint();

	_Infinity = false;
}

bool BigPoint::Verify(const Signature& Sig, const BigNum& GroupOrder, const BigNum& Hash, const BigPoint& PublicKey) const {
	BigNum S_Inverse_ = Sig._S.ModExp(GroupOrder - 2, GroupOrder);

	BigNum U_ = (Hash * S_Inverse_) % GroupOrder;

	BigNum  V_ = (Sig._R * S_Inverse_) % GroupOrder;

	return (((*this * U_) + PublicKey * V_)._x._Number) == (Sig._R);
}

Signature BigPoint::Sign(const PrivateKey& Key, const BigNum& GroupOrder, const BigNum& Hash) const {
	std::vector<uint8_t> Random_(32);
	RAND_bytes(Random_.data(), static_cast<int32_t>(Random_.size()));

	BigNum K_(BigNum(Random_) % GroupOrder);

	BigNum R_((*this * K_)._x._Number);

	BigNum K_Inverse_(K_.ModExp(GroupOrder - 2, GroupOrder));

	BigNum S_(((Hash + R_ * Key._Secret) * K_Inverse_) % GroupOrder);

	if (S_ > GroupOrder / 2)
		S_ = (GroupOrder - S_);

	return Signature(R_, S_);
}

bool Secp256k1_Verify(const Signature& Sig, const BigNum& Hash, const BigPoint& PublicKey) {
	return Secp256k1_Generator.Verify(Sig, Secp256k1_GroupOrder, Hash, PublicKey);
}

Signature Secp256k1_Sign(const PrivateKey& Key, const BigNum& Hash) {
	return Secp256k1_Generator.Sign(Key, Secp256k1_GroupOrder, Hash);
}
