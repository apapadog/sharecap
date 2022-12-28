
CC = gcc
CXX = g++
AR = ar
LD = ld

CFLAGS_WARNING += -Wall -Wextra -Wno-comment -Wno-sign-compare -Wno-missing-field-initializers -Wno-unused-parameter
CFLAGS_DEFINES += -D_GNU_SOURCE
CFLAGS_OPT += -O2 -g
CFLAGS += $(CFLAGS_ARCH) $(CFLAGS_DEFINES) $(CFLAGS_WARNING) -Wstrict-prototypes $(CFLAGS_INCLUDE) $(CFLAGS_OPT) $(CFLAGS_EXTRA)
CXXFLAGS += $(CFLAGS_ARCH) $(CFLAGS_DEFINES) $(CFLAGS_WARNING) $(CFLAGS_INCLUDE) $(CFLAGS_OPT) $(CFLAGS_EXTRA)
LDFLAGS_EXTRA_LIBS = -lpthread -lrt
LDFLAGS += $(CFLAGS_ARCH) $(LDFLAGS_USER) $(LDFLAGS_EXTRA_LIBS)

SRC = sharecap.c
UNIT_TEST_SRC = test_sharecap.cpp

UNIT_TESTS = $(UNIT_TEST_SRC:.cpp=)
%: %.cpp libsharecap.a
	$(CXX) $(CXXFLAGS) $^ -lgtest $(LDFLAGS) -o $@

OBJS = $(SRC:.c=.o)
%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $< $(LDFLAGS) -o $@

LIBS = $(OBJS:.o=.a)
%.a: %.o
	$(AR) crs $@ $<

libsharecap.mri: $(LIBS)
	echo $(LIBS)
	@echo "create libsharecap.a" > $@
	$(foreach arg,$^,echo addlib $(arg) >> $@;)
	@echo "save" >> $@
	@echo "end" >> $@

libsharecap.a: libsharecap.mri
	$(AR) -M < $^

.INTERMEDIATE : libsharecap.mri $(LIBS)

clean:
	rm -f *.o *.a $(UNIT_TESTS)

install:
	echo "no install yet"

.PHONY: clean install

all: libsharecap.a $(UNIT_TESTS)

.DEFAULT_GOAL := all

