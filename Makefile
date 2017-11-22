LDFLAGS=$(shell pkg-config --libs openssl) -pthread -ldl
CFLAGS=-O2 -std=c++11

all:
	g++ $(CFLAGS) tls-speed.cpp $(LDFLAGS) -o tls-speed
