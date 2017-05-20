cmake_minimum_required (VERSION 2.8)
project (sodiumpp)

if (CMAKE_VERSION VERSION_GREATER 3.0.0 OR CMAKE_VERSION VERSION_EQUAL 3.0.0)
cmake_policy(SET CMP0042 OLD)
endif ()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")# -std=c++11

add_library(sodiumpp SHARED sodiumpp.cpp)
target_link_libraries(sodiumpp ${SODIUM_LIBRARIES})

if (BUILD_TESTING)
    add_executable(example example.cpp)
    target_link_libraries(example sodiumpp)
endif (BUILD_TESTING)

install_files(/include .h)
install_targets(/lib sodiumpp)
