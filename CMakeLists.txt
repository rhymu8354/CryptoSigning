# CMakeLists.txt for CryptoSigning
#
# © 2018 by Richard Walters

cmake_minimum_required(VERSION 3.8)
set(This CryptoSigning)

set(Headers
    include/CryptoSigning/Sign.hpp
    include/CryptoSigning/Verify.hpp
)

set(Sources
    src/Sign.cpp
    src/Verify.cpp
)

add_library(${This} STATIC ${Sources} ${Headers})
set_target_properties(${This} PROPERTIES
    FOLDER Libraries
)

target_include_directories(${This} PUBLIC include)

target_link_libraries(${This} PUBLIC
    crypto
)
if (WIN32)
    target_link_libraries(${This} PUBLIC
        Ws2_32.lib
    )
endif (WIN32)

add_subdirectory(test)
