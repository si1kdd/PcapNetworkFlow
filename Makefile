LIBROOT		= /usr/local/lib
CXXFLAGS	= -Wall -Wextra -Wpedantic -std=c++11 -Os -O2
LDFLAGS		= -L$(LIBROOT) -I$(LIBROOT) -ltins -lpcap

PROGS		= pcap_network_flow

UNAME := $(shell uname -s)
ifeq ($(UNAME), $(filter $(UNAME), Darwin FreeBSD))
	CC = clang
else
	CC = gcc
endif


$(PROGS): pcap_network_flow.cc
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LDFLAGS)
	strip -s $(PROGS)
clean:
	rm -f $(PROGS) *.o
