# CMakeLists.txt for CryptoSigningTests
#
# © 2018 by Richard Walters

cmake_minimum_required(VERSION 3.8)
set(This CryptoSigningTests)

set(Sources
    src/SignTests.cpp
    src/VerifyTests.cpp
)

add_executable(${This} ${Sources})
set_target_properties(${This} PROPERTIES
    FOLDER Tests
)

target_link_libraries(${This} PUBLIC
    gtest_main
    CryptoSigning
)

add_test(
    NAME ${This}
    COMMAND ${This}
)
