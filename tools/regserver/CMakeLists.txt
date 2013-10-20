add_executable(regserver regserver.cpp)
install(TARGETS regserver
    RUNTIME DESTINATION tools)
