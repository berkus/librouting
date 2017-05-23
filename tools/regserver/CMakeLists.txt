add_executable(regserver regserver.cpp)
target_link_libraries(regserver routing uia arsenal
    ${Boost_LIBRARIES} sodiumpp ${CMAKE_THREAD_LIBS_INIT})
install(TARGETS regserver
    RUNTIME DESTINATION tools)
