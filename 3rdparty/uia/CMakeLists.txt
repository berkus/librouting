cmake_minimum_required(VERSION 2.8)
project(libuia)

if (NOT BUILD_IN_UVVY)
    include(cmake/setup.cmake)
    include_directories(3rdparty/endian 3rdparty/arsenal/include)
    include_directories(3rdparty)
endif()

include_directories(include)
add_subdirectory(lib)

if (BUILD_TESTING)
    add_subdirectory(tests)
endif (BUILD_TESTING)
