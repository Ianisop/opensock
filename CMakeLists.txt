cmake_minimum_required(VERSION 3.20)
project(opensock VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find OpenSSL first
find_package(OpenSSL REQUIRED)

# Create the library
add_library(opensock
    src/socket/websock.cpp
    src/socket/sslwebsock.cpp
)

# Public headers for users of the library
target_include_directories(opensock PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/socket
)

# Link dependencies
target_link_libraries(opensock
    PUBLIC

        OpenSSL::SSL

        OpenSSL::Crypto
    PRIVATE
        $<$<BOOL:${WIN32}>:ws2_32>
)

