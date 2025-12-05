cmake_minimum_required(VERSION 3.20)
project(opensock VERSION 0.1.0 LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)

add_library(opensock
    src/socket/websock.cpp
    src/socket/sslwebsock.cpp
)

target_include_directories(opensock
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/socket>

        $<INSTALL_INTERFACE:include>
)

target_sources(opensock

    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/socket/websock.h>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/socket/sslwebsock.h>
)

target_link_libraries(opensock
    PUBLIC OpenSSL::SSL OpenSSL::Crypto
    PRIVATE $<$<BOOL:${WIN32}>:ws2_32>
)

include(CMakePackageConfigHelpers)

install(TARGETS opensock
        EXPORT opensockTargets
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)

install(EXPORT opensockTargets
        FILE opensockTargets.cmake
        NAMESPACE opensock::
        DESTINATION lib/cmake/opensock)


write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/opensockConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/opensockConfigVersion.cmake"
    DESTINATION lib/cmake/opensock
)


