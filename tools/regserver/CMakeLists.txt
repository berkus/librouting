add_executable(regserver regserver.cpp)
target_link_libraries(regserver routing sss arsenal krypto
    ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})
install(TARGETS regserver
    RUNTIME DESTINATION tools)
