#include "Crypt.h"
#include <algorithm>

BigFieldElement BigFieldElement::operator^(BigNum exponent) const {
	if (exponent < 0) {
		exponent.set_absolute();
		return (*this ^ (prime - 2)) ^ exponent;
	}
	else {
		return BigFieldElement(number.mod_exp(exponent, prime), prime);
	}
}

BigFieldElement BigFieldElement::sqrt() const {
	if ((prime + 1) % 4 != 0)
		throw ArithmeticError(ArithmeticError::Type::UNDEFINED_OPERATION, "The Prime is not congruent to 3 modulo 4.");

	return *this ^ ((prime + 1) / 4);
}

// Encodes the signature as a DER in bytes in a vector.
std::vector<uint8_t> Signature::der_to_std_vec() {
	std::vector<uint8_t> bin;

	bin.push_back(0x30);

	auto r = this->r.to_std_vec();
	auto s = this->s.to_std_vec();

	bin.push_back(1 + 1 + r.size() + static_cast<uint64_t>((*(r.begin()) >= 0x80 ? 1 : 0)) + 
					1 + 1 + s.size() + static_cast<uint64_t>((*(s.begin()) >= 0x80 ? 1 : 0)));

	bin.push_back(0x02);

	bin.push_back(r.size() + static_cast<uint64_t>((*(r.begin()) >= 0x80 ? 1 : 0)));
	if (*(r.begin()) >= 0x80)
		bin.push_back(0x00);

	uint64_t position = bin.size();

	bin.resize(bin.size() + r.size());
	std::copy(r.begin(), r.end(), bin.begin() + position);

	bin.push_back(0x02);

	bin.push_back(s.size() + static_cast<uint64_t>((*(s.begin()) >= 0x80 ? 1 : 0)));
	if (*(s.begin()) >= 0x80)
		bin.push_back(0x00);

	position = bin.size();

	bin.resize(bin.size() + s.size());
	std::copy(s.begin(), s.end(), bin.begin() + position);

	return bin;
}

// Gets the DER encoding in a vector and sets the signature parameters.
void Signature::std_vec_to_der(const std::vector<uint8_t>& vector) {
	std::vector<uint8_t> r_var;
	std::vector<uint8_t> s_var;
	auto iterator = vector.begin();

	if (*iterator != 0x30)
		throw ParsingError(ParsingError::Type::UNEXPECTED_VALUE);
	iterator++;

	iterator++;

	if (*iterator != 0x02)
		throw ParsingError(ParsingError::Type::UNEXPECTED_VALUE,  "Invalid DER Signature encoding.");
	iterator++;

	uint8_t r_size = *iterator;

	iterator++;

	if (*iterator == 0x00) {
		iterator++;
		r_size--;
	}

	r_var.resize(r_size);

	std::copy(iterator, iterator + r_size, r_var.begin());

	iterator += r_size;


	if (*iterator != 0x02)
		throw ParsingError(ParsingError::Type::UNEXPECTED_VALUE, "Invalid DER Signature encoding.");
	iterator++;

	uint8_t s_size = *iterator;

	iterator++;

	if (*iterator == 0x00) {
		iterator++;
		s_size--;
	}

	s_var.resize(s_size);

	std::copy(iterator, iterator + s_size, s_var.begin());

	iterator += s_size;

	r = r_var;
	s = s_var;
}

std::vector<uint8_t> digest(const std::vector<uint8_t>& message, const std::string& digest_name) {
	std::unique_ptr<EVP_MD, decltype(&free_digest)> digest_algorithm(EVP_MD_fetch(nullptr, digest_name.c_str(), nullptr), &free_digest);
	std::unique_ptr<EVP_MD_CTX, decltype(&free_context)> digest_context(EVP_MD_CTX_new(), &free_context);

	if (digest_algorithm == nullptr) {
		throw CryptographyError(CryptographyError::Type::DIGEST_ALGORITHM_NOT_FOUND);
	}

	if (digest_context == nullptr) {
		EVP_MD_free(digest_algorithm.get());
		throw CryptographyError(CryptographyError::Type::DIGEST_CONTEXT_NOT_FOUND);
	}

	// Initialize the digest context(what performs the operations) with the required information(the digest algorithm).
	EVP_DigestInit_ex2(digest_context.get(), digest_algorithm.get(), nullptr);

	// Get the batch size of each round.
	const std::uint64_t batch_size = EVP_MD_block_size(digest_algorithm.get());
	std::uint64_t input_used = 0;

	// Process the input batch by batch.
	while (input_used < message.size()) {
		EVP_DigestUpdate(digest_context.get(), message.data() + input_used, std::min(batch_size, message.size() - input_used));
		input_used += std::min(batch_size, message.size() - input_used);
	}

	std::vector<uint8_t> result(EVP_MD_CTX_get_size(digest_context.get()), '\0');
	std::uint32_t result_size = 0;

	// Finalize the result and set the amount of space used.
	EVP_DigestFinal_ex(digest_context.get(), (uint8_t*)result.data(), &result_size);

	// Sometimes the space used is actually less than what EVP_MD_CTX_get_size(digest_context.get()) returns, 
	// so we make an adjustment, so it is not taken to be more than what it actually is.
	result.resize(result_size);

	return result;
}

std::vector<uint8_t> get_hash_160(const std::vector<uint8_t>& message) {
	// Hash160 is gotten by SHA256 and then RIPEMD160.
	auto sha256 = get_sha_256(message);

	auto hash160 = get_ripemd_160(sha256);

	return hash160;
}

BigPoint::BigPoint(const BigPoint& p) {
	if (p.infinity) {
		a = (p.a);
		b = (p.b);
		infinity = true;
	}
	else
	{
		x = (p.x);
		y = (p.y);
		a = (p.a);
		b = (p.b);
		infinity = false;

		// If the point is not the curve throw an error.
		if ((y * y) != ((x * x * x) + (a * x) + b))
			throw CryptographyError(CryptographyError::Type::INVALID_POINT);
	}
}

BigPoint& BigPoint::operator=(const BigPoint& p) {
	if (p.infinity) {
		a = (p.a);
		b = (p.b);
		infinity = true;
	}
	else
	{
		x = (p.x);
		y = (p.y);
		a = (p.a);
		b = (p.b);
		infinity = false;

		// If the point is not the curve throw an error.
		if ((y * y) != ((x * x * x) + (a * x) + b))
			throw CryptographyError(CryptographyError::Type::INVALID_POINT);
	}
	return *this;
}

BigPoint BigPoint::operator+(const BigPoint& other_point) const {
	if (!(other_point.a == a && other_point.b == b))
		throw CryptographyError(CryptographyError::Type::CURVE_MISMATCH);

	if (infinity)
		return other_point;

	if (other_point.infinity)
		return *this;

	if (other_point.x == x && y == (BigFieldElement(0, other_point.y.prime) - other_point.y))
		return BigPoint(a, b);

	if (other_point.x == x && (other_point.y == y) && (y == BigFieldElement(0, y.prime)))
		return BigPoint(a, b);

	BigFieldElement slope_val;

	if (other_point.x != x)
		slope_val = (other_point.y - y) / (other_point.x - x);
	else {
		slope_val = ((x * x * 3) + a) / (y * 2);
	}

	BigFieldElement x_val = ((slope_val * slope_val) - x) - other_point.x;

	BigFieldElement y_val = (slope_val * (x - x_val)) - y;

	return BigPoint(a, b, x_val, y_val);
}

BigPoint BigPoint::operator*(BigNum scalar) const {
	BigPoint result(a, b); // Point at infinity
	BigPoint temp_point = *this;

	while (scalar > 0) {
		if (scalar % 2 == 1) {
			result = result + temp_point;
		}
		temp_point = temp_point + temp_point;
		scalar = scalar / 2;
	}

	return result;
}

std::string BigPoint::uncompressed_sec_to_hex() const {
	const uint8_t byte_count = 64;

	if (infinity)
		throw CryptographyError(CryptographyError::Type::INVALID_POINT);

	std::string sec(byte_count * 2 + 2, '\0');
	std::string::iterator sec_iterator = sec.begin();
	*sec_iterator = '0';
	sec_iterator++;
	*sec_iterator = '4';
	sec_iterator++;

	auto sec_x = x.number.to_hex();

	uint8_t counter = 0;
	while (sec_x.size() + counter < byte_count) {
		*sec_iterator = '0';
		sec_iterator++;
		*sec_iterator = '0';
		sec_iterator++;
		++counter;
	}

	sec_iterator = std::copy(sec_x.begin(), sec_x.end(), sec_iterator);

	auto sec_y = y.number.to_hex();
	
	counter = 0;
	while (sec_y.size() + counter < byte_count) {
		*sec_iterator = '0';
		sec_iterator++;
		*sec_iterator = '0';
		sec_iterator++;
		++counter;
	}

	sec_iterator = std::copy(sec_y.begin(), sec_y.end(), sec_iterator);

	return sec;
}

std::string BigPoint::compressed_sec_to_hex() const {
	const uint8_t byte_count = 64;

	if (infinity)
		throw CryptographyError(CryptographyError::Type::INVALID_POINT);

	std::string sec(byte_count + 2, '\0');
	std::string::iterator sec_iterator = sec.begin();

	*sec_iterator = '0';
	sec_iterator++;
	*sec_iterator = ((y.number % 2 == 0) ? '2' : '3'); //Parity indicator.
	sec_iterator++;

	auto sec_x = x.number.to_hex();

	uint8_t counter = 0;
	while (sec_x.size() + counter < byte_count) {
		*sec_iterator = '0';
		sec_iterator++;
		*sec_iterator = '0';
		sec_iterator++;
		++counter;
	}

	std::copy(sec_x.begin(), sec_x.end(), sec_iterator);

	return sec;
}

void BigPoint::uncompressed_sec_from_std_vec(const std::vector<uint8_t>& sec) {
	const uint8_t byte_count = 32;

	std::pair<std::vector<uint8_t>, std::vector<uint8_t>> sec_x_y;

	std::vector<uint8_t>::const_iterator sec_iterator = sec.cbegin();
	if (*sec_iterator != 0x04)
		throw ParsingError(ParsingError::Type::INVALID_DATA);
		
	sec_iterator++; // Skip past the prefix.


	sec_x_y.first.resize(byte_count);
	std::copy_n(sec_iterator, byte_count, sec_x_y.first.begin());
	sec_iterator += byte_count;
	x = BigFieldElement(sec_x_y.first, a.prime);

	sec_x_y.second.resize(byte_count);
	std::copy_n(sec_iterator, byte_count, sec_x_y.second.begin());
	y = BigFieldElement(sec_x_y.second, a.prime);

	if (y * y != ((x * x * x) + (a * x) + b)) // Check for point validity.
		throw CryptographyError(CryptographyError::Type::INVALID_POINT);

	infinity = false;
}

void BigPoint::compressed_sec_from_std_vec(std::vector<uint8_t>&& sec) {
	const uint8_t parity = *(sec.begin()); //Parity.

	if (parity != 0x02 && parity != 0x03)
		throw ParsingError(ParsingError::Type::INVALID_DATA);		

	sec.erase(sec.begin()); //Remove the Parity indicator.

	x = BigFieldElement(sec, a.prime);

	y = ((x * x * x) + (a * x) + b).sqrt();

	if (parity == 0x02) {
		if (y.number % 2 == 1)
			y.number = y.prime - y.number;
	}
	else {
		if (y.number % 2 == 0)
			y.number = y.prime - y.number;
	}

	if (y * y != ((x * x * x) + (a * x) + b)) // Check for point validity.
		throw CryptographyError(CryptographyError::Type::INVALID_POINT);

	infinity = false;
}

void BigPoint::from_std_vec(std::vector<uint8_t>&& sec) {
	if (sec.size() == 33) { // The compressed public key representation uses only 33 bytes.
		compressed_sec_from_std_vec(std::move(sec));
	}
	else if (sec.size() == 65) { // The uncompressed public key representation uses only 65 bytes.
		uncompressed_sec_from_std_vec(sec);
	}
	else {
		throw ParsingError(ParsingError::Type::INVALID_DATA);		
	}
}

void BigPoint::from_std_vec(const std::vector<uint8_t>& sec) {
	if (sec.size() == 33) { // The compressed public key representation uses only 33 bytes.
		compressed_sec_from_std_vec(std::vector<uint8_t>(sec));
	}
	else if (sec.size() == 65) { // The uncompressed public key representation uses only 65 bytes.
		uncompressed_sec_from_std_vec(sec);
	}
	else {
		throw ParsingError(ParsingError::Type::INVALID_DATA);		
	}
}

void BigPoint::from_std_hex(const std::string& sec) {
	if (sec.size() == 66) { // The compressed public key representation uses only 33 bytes(66 in hexadecimal).
		uncompressed_sec_from_hex(sec);
	}
	else if (sec.size() == 130) { // The compressed public key representation uses only 65 bytes(130 in hexadecimal).
		compressed_sec_from_hex(sec);
	}
	else {
		throw ParsingError(ParsingError::Type::INVALID_DATA);		
	}
}


bool BigPoint::verify(const Signature& sig, const BigNum& group_order, const BigNum& hash, const BigPoint& public_key) const {
	BigNum s_inverse = sig.s.mod_exp(group_order - 2, group_order);

	BigNum u = (hash * s_inverse) % group_order;

	BigNum v = (sig.r * s_inverse) % group_order;

	return (((*this * u) + public_key * v).x.number) == (sig.r);
}

Signature BigPoint::sign(const PrivateKey& key, const BigNum& group_order, const BigNum& hash) const {
	std::vector<uint8_t> random_bytes(32);
	RAND_bytes(random_bytes.data(), static_cast<int32_t>(random_bytes.size()));

	BigNum k_val(BigNum(random_bytes) % group_order);

	BigNum r_val((*this * k_val).x.number);

	BigNum k_inverse(k_val.mod_exp(group_order - 2, group_order));

	BigNum s_val(((hash + r_val * key.secret) * k_inverse) % group_order);

	if (s_val > group_order / 2)
		s_val = (group_order - s_val);

	return Signature(r_val, s_val);
}

bool secp256k1_verify(const Signature& sig, const BigNum& hash, const BigPoint& public_key) {
	return Secp256k1_Generator.verify(sig, Secp256k1_GroupOrder, hash, public_key);
}

Signature secp256k1_sign(const PrivateKey& key, const BigNum& hash) {
	return Secp256k1_Generator.sign(key, Secp256k1_GroupOrder, hash);
}