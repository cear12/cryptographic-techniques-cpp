cmake_minimum_required(VERSION 3.16)
project(cryptotech CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(CRYPTOTECH_BUILD_EXAMPLES "Build examples/" ON)

add_library(cryptotech STATIC
    src/sha256.cpp
    src/aes128.cpp
    src/block_cipher_modes.cpp
    src/caesar_cipher.cpp
    src/substitution_cipher.cpp
    src/vigenere_cipher.cpp
    src/one_time_pad.cpp
    src/feistel_cipher.cpp
    src/salsa20.cpp
    src/kdf.cpp
    src/salt_techniques.cpp
    src/key_derivation.cpp
    src/sbox_design.cpp
)
target_include_directories(cryptotech PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(cryptotech PRIVATE $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>)

if(CRYPTOTECH_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
