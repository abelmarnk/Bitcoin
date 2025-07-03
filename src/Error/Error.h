#pragma once
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <string>
#include <stdexcept>


class CryptographyError : public std::runtime_error {
public:
    enum class Type {
        OS_ACCESS_FAILURE,         
        INVALID_POINT,              
        CURVE_MISMATCH,             
        SIGNATURE_VERIFICATION_FAILED,
        SIGNATURE_GENERATION_FAILED,
        DIGEST_ALGORITHM_NOT_FOUND,
        DIGEST_CONTEXT_NOT_FOUND,
        DIGEST_UPDATE_FAILED,
        DIGEST_INITIALIZATION_FAILED,
        DIGEST_FINILIZATION_FAILED,
        DIGEST_CONTEXT_CREATION_FAILED
    };

    CryptographyError(Type type, const std::string& message = "Cryptography Error")
        : std::runtime_error(message), error_type(type) {}

    Type get_type() const { return error_type; }

private:
    Type error_type;
};


enum class NetworkError:uint8_t{
    CONNECTION_FAILURE,
    TIMEOUT,
    INVALID_MESSAGE,
    CHECKSUM_MISMATCH,
    UNKNOWN_COMMAND,
    UNEXPECTED_COMMAND,
};

class NetworkErrorCategory : public boost::system::error_category {
public:
    const char* name() const noexcept override {
        return "network";
    }

    std::string message(int ev) const override {
        switch (static_cast<NetworkError>(ev)) {
            case NetworkError::CONNECTION_FAILURE: return "Connection failure";
            case NetworkError::TIMEOUT: return "Operation timed out";
            case NetworkError::INVALID_MESSAGE: return "Invalid message format";
            case NetworkError::CHECKSUM_MISMATCH: return "Checksum mismatch";
            case NetworkError::UNKNOWN_COMMAND: return "Unknown command received";
            case NetworkError::UNEXPECTED_COMMAND: return "Unexpected command received";
            default: return "Unknown network error";
        }
    }
};

inline const boost::system::error_category& network_error_category() {
    static NetworkErrorCategory instance;
    return instance;
}

inline boost::system::error_code make_error_code(NetworkError e) {
    return {static_cast<int>(e), network_error_category()};
}

namespace boost {
namespace system {
    template <>
    struct is_error_code_enum<NetworkError> : std::true_type {};
}}

class ScriptError : public std::runtime_error {
public:
    enum class Type {
        OPCODE_NOT_SUPPORTED,    
        FUNCTION_EXECUTION_FAILED,
        EVALUATION_FAILED,
        FUNCTION_CAST_FAILED,
        WITNESS_DATA_MISSING         
    };

    ScriptError(Type type, const std::string& message = "Script Error")
        : std::runtime_error(message), error_type(type) {}

    Type get_type() const { return error_type; }

private:
    Type error_type;
};

class TransactionError : public std::runtime_error {
public:
    enum class Type {
        
    };

    TransactionError(Type type, const std::string& message = "Transaction Error")
        : std::runtime_error(message), error_type(type) {}

    Type get_type() const { return error_type; }

private:
    Type error_type;
};

class ArithmeticError : public std::runtime_error {
public:
    enum class Type {
        OUT_OF_RANGE,            
        UNDEFINED_OPERATION,     
        DIVISION_BY_ZERO,        
        NULL_POINTER_ACCESS,
        NUMBER_IS_NULL      
    };

    ArithmeticError(Type type, const std::string& message = "Arithmetic Error")
        : std::runtime_error(message), error_type(type) {}

    Type get_type() const { return error_type; }

private:
    Type error_type;
};

class ParsingError: public std::runtime_error{
    public:
    enum class Type{
        SUCCESS = 0,
        INVALID_CHECKSUM,
        UNEXPECTED_VALUE,
        INVALID_MAGIC,
        INVALID_HEADER,
        INVALID_COMMAND,
        INVALID_DATA,
        OUT_OF_BOUNDS
    };

    ParsingError(Type type, const std::string& message = "Parsing Error")
        : std::runtime_error(message), error_type(type) {}

    Type get_type() const { return error_type; }

private:
    Type error_type;
};

class SerializingError: public std::runtime_error{
    public:
    enum class Type{
        INVALID_DATA
    };

    SerializingError(Type type, const std::string& message = "Serializing Error")
        : std::runtime_error(message), error_type(type) {}

    Type get_type() const { return error_type; }

private:
    Type error_type;
};


