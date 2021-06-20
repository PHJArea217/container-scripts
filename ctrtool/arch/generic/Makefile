CFLAGS ?= -O3 -g -Wall -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC $(CFLAGS_EXTRA)

all: arch.a

arch.a: syscall.o
	ar r $@ $<

syscall.o: syscall.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f syscall.o arch.a

.PHONY: all clean
