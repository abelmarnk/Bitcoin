cmake_minimum_required(VERSION 3.10)
project(BitcoinCpp)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Debug)

find_package(Boost REQUIRED COMPONENTS
    system
    filesystem
    thread
    chrono
)

find_package(OpenSSL REQUIRED)


set(APP_SOURCES
    src/Compute/Compute.cpp
    src/Crypt/Crypt.cpp
    src/Serial/Serial.cpp
    src/Script/Script.cpp
    src/Transaction/Transaction.cpp
    src/Varint/Varint.cpp
    src/Block/Block.cpp
    src/Network/Network.cpp
    "src/Debug functions/Debug functions.cpp"
)

set(APP_HEADERS
    src/Compute/Compute.h
    src/Crypt/Crypt.h
    src/Serial/Serial.h
    src/Script/Script.h
    src/Transaction/Transaction.h
    src/Varint/Varint.h
    src/Block/Block.h
    src/Network/Network.h
    "src/Debug functions/Debug functions.h"
)



set(TEST_SOURCES
    "tests/crypt.cpp"
    "tests/script.cpp"
    "tests/transaction.cpp"
    "tests/digest.cpp"
    "tests/block.cpp"
    "tests/serial.cpp"
    "tests/network.cpp"
    "/home/abel/Documents/-Libraries/catch/catch_amalgamated.cpp"
)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Using debug sanitizers")

    # Apply these options to both your main executable and your test executable
    add_compile_options(-g -fsanitize=address -fno-omit-frame-pointer -O1)
    add_link_options(-fsanitize=address)
endif()


# ---Tests---
add_executable(BitcoinCpp_Tests ${APP_SOURCES} ${TEST_SOURCES}  ${APP_HEADERS})

# Include directories for the test executable
target_include_directories(BitcoinCpp_Tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/
    /home/abel/Documents/-Libraries/
    ${Boost_INCLUDE_DIRS}
)


target_compile_definitions(BitcoinCpp_Tests PRIVATE CATCH_CONFIG_MAIN)

target_link_libraries(BitcoinCpp_Tests
    PRIVATE
        Boost::chrono
        Boost::system
        Boost::thread
        OpenSSL::SSL
        OpenSSL::Crypto
)

enable_testing()
include(CTest)

add_test(
    NAME BitcoinCpp_CatchTests
    COMMAND BitcoinCpp_Tests
)
