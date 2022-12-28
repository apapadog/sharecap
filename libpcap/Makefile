
CC = gcc
CXX = g++
LD = ld

LIBS = ../src/libsharecap.a

CFLAGS_WARNING += -Wall -Wextra -Wno-comment -Wno-sign-compare -Wno-missing-field-initializers -Wno-unused-parameter
CFLAGS_DEFINES += -D_GNU_SOURCE
CFLAGS_OPT += -O2 -g
CFLAGS += $(CFLAGS_ARCH) $(CFLAGS_DEFINES) $(CFLAGS_WARNING) -Wstrict-prototypes $(CFLAGS_INCLUDE) $(CFLAGS_OPT) $(CFLAGS_EXTRA)
CXXFLAGS += $(CFLAGS_ARCH) $(CFLAGS_DEFINES) $(CFLAGS_WARNING) $(CFLAGS_INCLUDE) $(CFLAGS_OPT) $(CFLAGS_EXTRA)
LDFLAGS_EXTRA_LIBS = $(LIBS) -lpcap -lrt -lpthread -ldl
LDFLAGS += $(CFLAGS_ARCH) $(LDFLAGS_USER) $(LDFLAGS_EXTRA_LIBS)

SRC = pcap_wrapper.c

libpcap.so: pcap_wrapper.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< $(LDFLAGS)

clean:
	rm -f libpcap.so

all: libpcap.so

.DEFAULT_GOAL := all

