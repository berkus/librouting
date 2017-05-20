cmake_minimum_required(VERSION 3.8)
project(libuia)

if (NOT BUILD_IN_UVVY)
    include(cmake/setup.cmake)
    include_directories(3rdparty/arsenal/include)
    add_subdirectory(3rdparty/arsenal/lib)
endif()

include_directories(include)
add_subdirectory(lib)

if (BUILD_TESTING)
    add_subdirectory(tests)
endif (BUILD_TESTING)
