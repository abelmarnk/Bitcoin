#pragma once
#include <span>
#include <iostream>
#include <stdexcept>
#include <openssl/evp.h>
#include "../Error/Error.h"
#include "../Compute/Compute.h"
#include "../Debug functions/Debug functions.h"

class BigFieldElement {
public:

    BigFieldElement(const BigNum& number, const BigNum& prime) :number(number), prime(prime) {
        if (number < 0)
            throw ArithmeticError(ArithmeticError::Type::OUT_OF_RANGE, "Number < 0");

        if (number > (prime - 1))
            throw ArithmeticError(ArithmeticError::Type::OUT_OF_RANGE, "Number > Prime - 1");
    }

    BigFieldElement(const BigFieldElement& element) {
        number = element.number;
        prime = element.prime;
    }

    BigFieldElement& operator=(const BigFieldElement& element) {
        number = element.number;
        prime = element.prime;
        return *this;
    }

    BigFieldElement() : number(), prime() {}

    ~BigFieldElement() {
    }

    bool operator==(const BigFieldElement& other_element) const {
        if (number == other_element.number)
            if (prime == other_element.prime)
                return true;
        return false;
    }

    bool operator!=(const BigFieldElement& other_element) const {
        return !(other_element == *this);
    }

    BigFieldElement operator+(const BigNum& element) const {
        return BigFieldElement((number + element) % prime, prime);
    }

    BigFieldElement operator+(const BigFieldElement& element) const {
        if (prime != element.prime)
            throw ArithmeticError(ArithmeticError::Type::UNDEFINED_OPERATION, 
            "Only elements in the same field can added together");


        return BigFieldElement((number + element.number) % prime, prime);
    }

    BigFieldElement operator-(const BigNum& element) const {
        return BigFieldElement((number - element) % prime, prime);
    }

    BigFieldElement operator-(const BigFieldElement& element) const {
        if (prime != element.prime)
            throw ArithmeticError(ArithmeticError::Type::UNDEFINED_OPERATION, 
            "Only elements in the same field can taken from each other together");

        return BigFieldElement((number - element.number) % prime, prime);
    }

    BigFieldElement operator*(const BigNum& element) const {
        return BigFieldElement((number * element) % prime, prime);
    }

    BigFieldElement operator*(const BigFieldElement& element) const {
        if (prime != element.prime)
            throw ArithmeticError(ArithmeticError::Type::UNDEFINED_OPERATION, 
            "Only elements in the same field can multiplied together");

        return BigFieldElement((number * element.number) % prime, prime);
    }

    BigFieldElement operator/(const BigFieldElement& element) const {
        if (prime != element.prime)
            throw ArithmeticError(ArithmeticError::Type::UNDEFINED_OPERATION, 
            "Only elements in the same field can be divided against each together");

            // We find the inverse of "element" in the field using Fermat's last theorem and take it's product with "number"
        return BigFieldElement((number * (element.number.mod_exp(prime - 2, prime))) % prime, prime);
    }

    BigFieldElement operator^(BigNum exponent) const;

    BigFieldElement sqrt() const;

    BigNum number; // The number in the field.
    BigNum prime; // The size of the field, we are working with prime fields here.
};


class Signature {
public:
    Signature(const Signature& signature):r(signature.r), s(signature.s){

    }

    Signature(Signature&& signature):r(std::move(signature.r)), s(std::move(signature.s)){

    }

    Signature(const BigNum& r, const BigNum& s) :r(r), s(s) {
    }

    Signature(BigNum&& r, BigNum&& s) :r(std::move(r)), s(std::move(s)) {
    }

    Signature(const std::vector<uint8_t>& vector_bytes) {
        std_vec_to_der(vector_bytes);
    }

    std::vector<uint8_t> der_to_std_vec();

    virtual void std_vec_to_der(const std::vector<uint8_t>&);

    BigNum  r;
    BigNum  s;
};

class BitcoinSignature: public Signature {
public:

    BitcoinSignature(const BigNum& r, const BigNum& s) :Signature(r,s){
    }

    BitcoinSignature(BigNum&& r, BigNum&& s) :Signature(r,s){
    }

    BitcoinSignature(const std::vector<uint8_t>& vector_bytes):Signature(vector_bytes) {
    }

    BitcoinSignature(const Signature& signature):Signature(signature){

    }

    BitcoinSignature(Signature&& signature):Signature(signature){

    }

    std::vector<uint8_t> der_to_std_vec(uint8_t sighash_type = 0x01/*SIGHASH ALL*/){
        auto result = this->Signature::der_to_std_vec();

        result.push_back(sighash_type);

        return result;
    }


};

class PrivateKey;

class BigPoint {
public:

    BigPoint(const BigFieldElement& a, const BigFieldElement& b, const BigFieldElement& x, const BigFieldElement& y) :a(a), b(b), x(x), y(y), infinity(false) {
        if ((y * y) != ((x * x * x) + (a * x) + b))
            throw CryptographyError(CryptographyError::Type::CURVE_MISMATCH);
    }

    BigPoint(const BigPoint& p);

    BigPoint& operator=(const BigPoint& p);

    BigPoint(const BigFieldElement& a, const BigFieldElement& b) :a(a), b(b), infinity(true) {}

    BigPoint() :a(), b(), infinity(true) {
    }

    bool operator==(const BigPoint& other_point) const {
        return (other_point.a == a && other_point.b == b && other_point.x == x && other_point.y == y);
    }

    BigPoint operator+(const BigPoint& other_point) const;

    BigPoint operator*(BigNum scalar) const;

    std::string uncompressed_sec_to_hex() const;

    std::string compressed_sec_to_hex() const;

    void uncompressed_sec_from_std_vec(const std::vector<uint8_t>& sec);

    void  compressed_sec_from_std_vec(std::vector<uint8_t>&& sec);

    // Change the next 4 lazy implementations.
    std::vector<uint8_t> uncompressed_sec_to_std_vec() const {
        auto result = hex_to_std_vec(uncompressed_sec_to_hex());
        //HexDump(result.begin(), result.size());
        return result;
    }

    std::vector<uint8_t> compressed_sec_to_std_vec() const {
        return hex_to_std_vec(compressed_sec_to_hex());
    }

    void uncompressed_sec_from_hex(const std::string& sec) {
        return uncompressed_sec_from_std_vec(hex_to_std_vec(sec));
    }

    void compressed_sec_from_hex(const std::string& sec) {
        compressed_sec_from_std_vec(hex_to_std_vec(sec));
    }

    void from_std_vec(std::vector<uint8_t>&& sec);

    void from_std_vec(const std::vector<uint8_t>& sec);

    void from_std_hex(const std::string& sec);

    bool verify(const Signature& sig, const BigNum& group_order, const BigNum& hash, const BigPoint& public_key) const;

    Signature sign(const PrivateKey& key, const BigNum& group_order, const BigNum& hash) const;

    bool infinity; // Indicator for if this point is the point at infinity
    BigFieldElement a; // Curve parameter
    BigFieldElement b; // Curve parameter
    BigFieldElement x; // Location on the plane
    BigFieldElement y; // Location on the plane
};

class PrivateKey {
public:
    PrivateKey(const BigNum& secret, const BigPoint& generator) :secret(secret), pubkey(generator* secret) {}

    BigNum secret;
    BigPoint pubkey;
};

struct SHA256_tag {};
struct HASH256_tag {};
struct HASH160_tag {};

template<typename T>
concept ValidDigestTag = 
    std::same_as<T, SHA256_tag> ||
    std::same_as<T, HASH256_tag> ||
    std::same_as<T, HASH160_tag>;

template<ValidDigestTag DigestTag>
class DigestStream {
public:
    DigestStream():context(new_context()), block_size(EVP_MD_block_size(EVP_sha256())){
        // All hash functions used in this program(Except for murmur hash which isn't used anywhere though) are based off SHA256.
        initialize_context(context.get(), EVP_sha256());
    }

    void update(const std::span<const uint8_t>& data) {
        update(data.data(), data.size());
    }

    template<typename It>
    requires std::contiguous_iterator<It> &&
         std::integral<std::iter_value_t<It>> && (sizeof(std::iter_value_t<It>) == 1)
    void update(It begin, size_t length) {
        update(reinterpret_cast<const uint8_t*>(&*begin), length);
    }

    std::vector<uint8_t> finalize() {
        if constexpr (std::is_same_v<DigestTag, SHA256_tag>) {
            return finalize(this->context.get(), EVP_sha256());
        } else if constexpr (std::is_same_v<DigestTag, HASH256_tag>) {
            auto sha = finalize(this->context.get(), EVP_sha256());
            return sha_256(sha);
        } else if constexpr (std::is_same_v<DigestTag, HASH160_tag>) {
            auto sha = finalize(this->context.get(), EVP_sha256());
            return ripemd_160(sha);
        }
    }
    
    static std::vector<uint8_t> digest(const std::span<const uint8_t>& data) {
        return digest(data.data(), data.size());
    }

    template<typename It>
    requires std::contiguous_iterator<It> &&
         std::integral<std::iter_value_t<It>> && (sizeof(std::iter_value_t<It>) == 1)
    static std::vector<uint8_t> digest(It begin, size_t length) {
        return digest(reinterpret_cast<const uint8_t*>(&*begin), length);
    }

private:
using DigestContextType = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

    static std::vector<uint8_t> digest(const uint8_t* data, size_t length) {
        DigestStream stream;
        stream.update(data, length);
        return stream.finalize();
    }

    void update(const uint8_t* data, size_t length) {
        size_t offset = 0;
        while (offset < length) {
            size_t chunk = std::min(block_size, length - offset);
            if (EVP_DigestUpdate(this->context.get(), data + offset, chunk) != 1) {
                throw CryptographyError(CryptographyError::Type::DIGEST_UPDATE_FAILED, "Digest update failed");
            }
            offset += chunk;
        }
    }

    static DigestContextType new_context() {
        EVP_MD_CTX* context_ = EVP_MD_CTX_new();
        if (!context_){
            throw CryptographyError(CryptographyError::Type::DIGEST_CONTEXT_CREATION_FAILED, "Digest context creation failed");
        }
        return DigestContextType(context_, &EVP_MD_CTX_free);
    }

    static void initialize_context(EVP_MD_CTX* context, const EVP_MD * digest) {
        if (EVP_DigestInit_ex2(context, digest, nullptr) != 1){
            throw CryptographyError(CryptographyError::Type::DIGEST_INITIALIZATION_FAILED, "Digest initialization failed");
        }
    }

    static std::vector<uint8_t> finalize(EVP_MD_CTX* context_,const EVP_MD* digest) {
        std::vector<uint8_t> output(EVP_MD_CTX_get_size(context_), '\0');
        unsigned int output_length = 0;
        if (EVP_DigestFinal_ex(context_, output.data(), &output_length) != 1){
            throw CryptographyError(CryptographyError::Type::DIGEST_FINILIZATION_FAILED, "Digest finalization failed");
        }
        output.resize(output_length);
        return output;
    }

    static std::vector<uint8_t> sha_256(const std::vector<uint8_t>& input) {
        auto context = new_context();
        auto block_size = EVP_MD_block_size(EVP_sha256());
        initialize_context(context.get(), EVP_sha256());
        size_t offset = 0;
        while (offset < input.size()) {
            size_t chunk = std::min(static_cast<size_t>(block_size), input.size() - offset);
            if (EVP_DigestUpdate(context.get(), input.data() + offset, chunk) != 1) {
                throw CryptographyError(CryptographyError::Type::DIGEST_UPDATE_FAILED, "SHA256 Digest update failed");
            }
            offset += chunk;
        }
        return finalize(context.get(), EVP_sha256());
    }

    std::vector<uint8_t> ripemd_160(const std::vector<uint8_t>& input) {
        auto context = new_context();
        auto block_size = EVP_MD_block_size(EVP_ripemd160());
        initialize_context(context.get(), EVP_ripemd160());
        size_t offset = 0;
        while (offset < input.size()) {
            size_t chunk = std::min(static_cast<size_t>(block_size), input.size() - offset);
            if (EVP_DigestUpdate(context.get(), input.data() + offset, chunk) != 1) {
                throw CryptographyError(CryptographyError::Type::DIGEST_UPDATE_FAILED, "RIPEMD160 Digest update failed");
            }
            offset += chunk;
        }
        return finalize(context.get(), EVP_ripemd160());
    }

    DigestContextType context;
    size_t block_size;
};


inline void free_digest(EVP_MD* md) {
    EVP_MD_free(md);
}

inline void free_context(EVP_MD_CTX* md) {
    EVP_MD_CTX_free(md);
}

std::vector<uint8_t> digest(const std::vector<uint8_t>& message, const std::string& digest_name);

inline std::vector<uint8_t> get_sha_256(const std::vector<uint8_t>& message) {
    return digest(message, "SHA256");
}

inline std::vector<uint8_t> get_hash_256(const std::vector<uint8_t> &message){
    return get_sha_256(get_sha_256(message));
}

inline std::vector<uint8_t> get_ripemd_160(const std::vector<uint8_t>& message) {
    return digest(message, "RIPEMD160");
}

std::vector<uint8_t> get_hash_160(const std::vector<uint8_t>& message);


const BigNum Secp256k1_Prime((BigNum(2) ^ 256) - (BigNum(2) ^ 32) - 977);

const BigNum Secp256k1_GroupOrder("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

const BigFieldElement Secp256k1_a(0, Secp256k1_Prime);

const BigFieldElement Secp256k1_b(7, Secp256k1_Prime);

const BigFieldElement Secp256k1_x(BigNum("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), Secp256k1_Prime);

const BigFieldElement Secp256k1_y(BigNum("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"), Secp256k1_Prime);

const BigPoint Secp256k1_Generator(Secp256k1_a, Secp256k1_b, Secp256k1_x, Secp256k1_y);

bool secp256k1_verify(const Signature& sig, const BigNum& hash,const BigPoint& public_key);

Signature secp256k1_sign(const PrivateKey& key, const BigNum& hash);