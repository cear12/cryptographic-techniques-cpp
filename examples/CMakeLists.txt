add_executable(crypto_demo demo.cpp)
target_link_libraries(crypto_demo PRIVATE cryptotech)

# The demo runs known-answer self-checks and exits non-zero on failure.
add_test(NAME crypto_demo COMMAND crypto_demo)
