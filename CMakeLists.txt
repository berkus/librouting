cmake_minimum_required(VERSION 3.8)

if (NOT BUILD_IN_UVVY)
    include(cmake/setup.cmake)
    include_directories(3rdparty) #sodiumpp
    include(FindSodium)
    include_directories(${SODIUM_INCLUDE_DIRS})
    add_subdirectory(3rdparty/sodiumpp)
    include_directories(3rdparty/arsenal/include)
    add_subdirectory(3rdparty/arsenal/lib)
    include_directories(3rdparty/uia/include)
    add_subdirectory(3rdparty/uia/lib)
endif()

include_directories(include)
add_subdirectory(lib)
add_subdirectory(tools/regserver)

if (BUILD_TESTING)
    #add_subdirectory(tests)
endif (BUILD_TESTING)
