#pragma once
#include "Compute.h"
#include <openssl/rand.h>


class BigFieldElement {
public:
	class OutOfRange {
	public:
		OutOfRange(std::string Message) :Message(Message) {}
		std::string Message;
	};

	class UndefinedOperation {
	public:
		UndefinedOperation(std::string Message) :Message(Message) {}
		std::string Message;
	};

	BigFieldElement(const BigNum& Number, const BigNum& Prime) :_Number(Number), _Prime(Prime) {
		//Is the number 0?
		if (_Number < 0)
			throw OutOfRange("Number < 0");

		// Check of the number is greater than prime - 1.
		if (_Number > (_Prime - 1))
			throw OutOfRange("Number > Prime - 1");
	}

	BigFieldElement(const BigFieldElement& Element) {
		_Number = Element._Number;
		_Prime = Element._Prime;
	}

	BigFieldElement& operator=(const BigFieldElement& Element) {
		_Number = Element._Number;
		_Prime = Element._Prime;
		return *this;
	}

	BigFieldElement() : _Number(), _Prime() {}

	~BigFieldElement() {
	}

	bool operator==(const BigFieldElement& OtherElement) const {
		if (_Number == OtherElement._Number)
			if (_Prime == OtherElement._Prime)
				return true;
		return false;
	}

	bool operator!=(const BigFieldElement& OtherElement) const {
		return !(OtherElement == *this);
	}

	BigFieldElement operator+(const BigNum& Element) const {
		return BigFieldElement((_Number + Element) % _Prime, _Prime);
	}

	BigFieldElement operator+(const BigFieldElement& Element) const {
		if (_Prime != Element._Prime)
			throw UndefinedOperation("Only elements in the same field can be added together.");

		return BigFieldElement((_Number + Element._Number) % _Prime, _Prime);
	}

	BigFieldElement operator-(const BigNum& Element) const {
		return BigFieldElement((_Number - Element) % _Prime, _Prime);
	}

	BigFieldElement operator-(const BigFieldElement& Element) const {
		if (_Prime != Element._Prime)
			throw UndefinedOperation("Only elements in the same field can be added together.");

		return BigFieldElement((_Number - Element._Number) % _Prime, _Prime);
	}

	BigFieldElement operator*(const BigNum& Element) const {
		return BigFieldElement((_Number * Element) % _Prime, _Prime);
	}

	BigFieldElement operator*(const BigFieldElement& Element) const {
		if (_Prime != Element._Prime)
			throw UndefinedOperation("Only elements in the same field can be added together.");

		return BigFieldElement((_Number * Element._Number) % _Prime, _Prime);
	}

	BigFieldElement operator/(const BigFieldElement& Element) const {
		if (_Prime != Element._Prime)
			throw UndefinedOperation("Only elements in the same field can be added together.");

		return BigFieldElement((_Number * (Element._Number.ModExp(_Prime - 2, _Prime))) % _Prime, _Prime);
	}

	BigFieldElement operator^(BigNum Exponent) const;

	BigFieldElement Sqrt() const;

	BigNum _Number;
	BigNum _Prime;
};

inline std::vector<uint8_t> HexToStdVec(const std::string& Hex) {
	/*std::vector<uint8_t> Bin;

	uint8_t Temp = 0;

	std::string::iterator Hex_Iterator = Hex.begin();

	while (Hex_Iterator != Hex.end()) {
		Temp = 0;

		if (*Hex_Iterator >= '0' && *Hex_Iterator <= '9') {
			Temp = 16 * ((*Hex_Iterator) - '0');
		}
		else
			if (*Hex_Iterator >= 'a' && *Hex_Iterator <= 'f') {
				Temp = 16 * (((*Hex_Iterator) - 'a') + 10);
			}
			else
				throw;
		Hex_Iterator++;

		if (*Hex_Iterator >= '0' && *Hex_Iterator <= '9') {
			Temp += ((*Hex_Iterator) - '0');
		}
		else
			if (*Hex_Iterator >= 'a' && *Hex_Iterator <= 'f') {
				Temp += (((*Hex_Iterator) - 'a') + 10);
			}
			else
				throw;
		Hex_Iterator++;

		Bin.push_back(Temp);
	}*/
	return BigNum(Hex).ToStdVec();
}

inline std::string StdVecToHex(const std::vector<uint8_t>& Vector) {
	return BigNum(Vector).ToHex();
}
class Signature {
public:

	class InvalidVector {

	};

	Signature(const BigNum& R, const BigNum& S) :_R(R), _S(S) {
	}

	Signature(const std::vector<uint8_t>& Vector) {
		StdVecToDER(Vector);
	}

	std::vector<uint8_t> DERtoStdVec();

	void StdVecToDER(const std::vector<uint8_t>& Vector);

	BigNum  _R;
	BigNum  _S;
};

class PrivateKey;

class BigPoint {
public:
	class InvalidPoint {
	};
	class CurveMismatch {
	};

	BigPoint(const BigFieldElement& a, const BigFieldElement& b, const BigFieldElement& x, const BigFieldElement& y) :_a(a), _b(b), _x(x), _y(y), _Infinity(false) {
		if ((y * y) != ((x * x * x) + (a * x) + b))
			throw InvalidPoint();
	}

	BigPoint(const BigPoint& P);

	BigPoint& operator=(const BigPoint& P);

	BigPoint(const BigFieldElement& a, const BigFieldElement& b) :_a(a), _b(b), _Infinity(true) {}

	BigPoint() :_a(), _b(), _Infinity(true) {
	}

	bool operator==(const BigPoint& OtherPoint) const {
		return (OtherPoint._a == _a && OtherPoint._b == _b && OtherPoint._x == _x && OtherPoint._y == _y);
	}

	BigPoint operator+(const BigPoint& OtherPoint) const;

	BigPoint operator*(BigNum Scalar) const;

	std::string UncompressedSecToHex() const;

	std::string CompressedSecToHex() const;

	void UncompressedSecFromStdVec(const std::vector<uint8_t>& Sec);

	void  CompressedSecFromStdVec(std::vector<uint8_t> Sec);

	std::vector<uint8_t> UncompressedSecToStdVec() const {
		return HexToStdVec(UncompressedSecToHex());
	}

	std::vector<uint8_t> CompressedSecToStdVec() const {
		return HexToStdVec(CompressedSecToHex());
	}

	void UncompressedSecFromHex(const std::string& Sec) {
		return UncompressedSecFromStdVec(HexToStdVec(Sec));
	}

	void CompressedSecFromHex(const std::string& Sec) {
		CompressedSecFromStdVec(HexToStdVec(Sec));
	}

	bool Verify(const Signature& Sig, const BigNum& GroupOrder, const BigNum& Hash, const BigPoint& PublicKey) const;

	Signature Sign(const PrivateKey& Key, const BigNum& GroupOrder, const BigNum& Hash) const;

	bool _Infinity;
	BigFieldElement _a;
	BigFieldElement _b;
	BigFieldElement _x;
	BigFieldElement _y;
};

class PrivateKey {
public:
	PrivateKey(const BigNum& Secret, const BigPoint& Generator) :_Secret(Secret), _PublicKey(Generator* _Secret) {}

	BigNum _Secret;
	BigPoint _PublicKey;
};

inline void FreeDigest(EVP_MD* MD) {
	EVP_MD_free(MD);
}

inline void FreeContext(EVP_MD_CTX* MD) {
	EVP_MD_CTX_free(MD);
}

std::vector<uint8_t> Digest(const std::vector<uint8_t>& Message, const std::string& Digest);

inline std::vector<uint8_t> GetSHA256(const std::vector<uint8_t>& Message) {
	return Digest(Message, "SHA256");
}

inline std::vector<uint8_t> GetRIPEMD160(const std::vector<uint8_t>& Message) {
	return Digest(Message, "RIPEMD160");
}

std::vector<uint8_t> GetHASH160(const std::vector<uint8_t>& Message);


const BigNum Secp256k1_Prime((BigNum(2) ^ 256) - (BigNum(2) ^ 32) - 977);

const BigNum Secp256k1_GroupOrder("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

const BigFieldElement Secp256k1_a(0, Secp256k1_Prime);

const BigFieldElement Secp256k1_b(7, Secp256k1_Prime);

const BigFieldElement Secp256k1_x(BigNum("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), Secp256k1_Prime);

const BigFieldElement Secp256k1_y(BigNum("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"), Secp256k1_Prime);

const BigPoint Secp256k1_Generator(Secp256k1_a, Secp256k1_b, Secp256k1_x, Secp256k1_y);

bool Secp256k1_Verify(const Signature& Sig, const BigNum& Hash,const BigPoint& PublicKey);

Signature Secp256k1_Sign(const PrivateKey& Key, const BigNum& Hash);