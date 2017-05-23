cmake_minimum_required (VERSION 3.8)
project (sodiumpp)

if (CMAKE_VERSION VERSION_GREATER 3.0.0 OR CMAKE_VERSION VERSION_EQUAL 3.0.0)
    cmake_policy(SET CMP0042 OLD)
endif ()

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")
include(FindSodium)
include_directories(${SODIUM_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -g")

if(SODIUMPP_MACPORTS)
    include_directories("/opt/local/include")
    link_directories("/opt/local/lib")
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/sodiumpp/include)

if(SODIUMPP_STATIC AND SODIUM_LIBRARIES)
    add_library(sodiumpp STATIC sodiumpp/sodiumpp.cpp sodiumpp/z85/z85.c sodiumpp/z85/z85_impl.cpp)
    set(SODIUMLIB ${SODIUM_LIBRARIES})
else()
    if (NOT SODIUMPP_STATIC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
        add_library(sodiumpp SHARED sodiumpp/sodiumpp.cpp sodiumpp/z85/z85.c sodiumpp/z85/z85_impl.cpp)
        target_link_libraries(sodiumpp ${SODIUM_SHARED_LIBRARIES})
        set(SODIUMLIB ${SODIUM_SHARED_LIBRARIES})
    else()
        message(FATAL_ERROR "Static sodium library requested, but not found")
    endif()
endif()

if(SODIUMPP_EXAMPLE)
    add_executable(example sodiumpp/example.cpp)
    target_link_libraries(example sodiumpp ${SODIUMLIB})
endif()

if(SODIUMPP_TEST)
    add_executable(tests sodiumpp/test.cpp)
    target_link_libraries(tests sodiumpp ${SODIUMLIB})
endif()

install(DIRECTORY sodiumpp/include/sodiumpp DESTINATION include)
install(TARGETS sodiumpp DESTINATION lib)
