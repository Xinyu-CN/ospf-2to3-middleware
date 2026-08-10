CXX ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic
CPPFLAGS ?= -Iinclude

LIB_SOURCES = src/fib.cpp src/gateway.cpp src/lsa.cpp src/neighbor.cpp src/ospf_packet.cpp src/raw_socket.cpp src/ospf_speaker.cpp

.PHONY: all test clean

all: ospf-gateway ospf-gatewayd ospf-gateway-tests ospf-gateway-protocol-tests

ospf-gateway: $(LIB_SOURCES) src/main.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@

ospf-gatewayd: $(LIB_SOURCES) src/daemon_main.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@

ospf-gateway-tests: $(LIB_SOURCES) tests/test_gateway.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@

ospf-gateway-protocol-tests: $(LIB_SOURCES) tests/test_protocol.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $^ -o $@

test: ospf-gateway-tests ospf-gateway-protocol-tests
	./ospf-gateway-tests
	./ospf-gateway-protocol-tests

clean:
	rm -f ospf-gateway ospf-gatewayd ospf-gateway-tests ospf-gateway-protocol-tests
