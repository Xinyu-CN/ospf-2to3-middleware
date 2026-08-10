cmake_minimum_required(VERSION 3.16)

project(ospf_gateway VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(ospf_gateway
    src/gateway.cpp
    src/fib.cpp
    src/lsa.cpp
    src/neighbor.cpp
    src/ospf_packet.cpp
    src/raw_socket.cpp
    src/ospf_speaker.cpp
)

target_include_directories(ospf_gateway
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if (MSVC)
    target_compile_options(ospf_gateway PRIVATE /W4 /permissive-)
else()
    target_compile_options(ospf_gateway PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(ospf-gateway
    src/main.cpp
)
target_link_libraries(ospf-gateway PRIVATE ospf_gateway)

add_executable(ospf-gatewayd
    src/daemon_main.cpp
)
target_link_libraries(ospf-gatewayd PRIVATE ospf_gateway)

enable_testing()

add_executable(ospf-gateway-tests
    tests/test_gateway.cpp
)
target_link_libraries(ospf-gateway-tests PRIVATE ospf_gateway)

add_executable(ospf-gateway-protocol-tests
    tests/test_protocol.cpp
)
target_link_libraries(ospf-gateway-protocol-tests PRIVATE ospf_gateway)

add_test(NAME ospf-gateway-tests COMMAND ospf-gateway-tests)
add_test(NAME ospf-gateway-protocol-tests COMMAND ospf-gateway-protocol-tests)
