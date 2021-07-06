CFLAGS ?= -O3 -g -Wall -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC $(CFLAGS_EXTRA)
AR := $(CROSS_COMPILE)ar

all: arch.a

arch.a: syscall.o
	$(AR) r $@ $<

syscall.o: syscall.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f syscall.o arch.a

.PHONY: all clean
