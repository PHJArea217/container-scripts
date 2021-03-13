CC ?= gcc
CCLD ?= $(CC)
AR ?= ar
CFLAGS ?= -O2 -g -fvisibility=hidden -fstack-protector-strong -fstack-clash-protection -fcf-protection=full -D_FORTIFY_SOURCE=2 -fPIC
CCLDFLAGS ?= -shared -Wl,-z,relro,-z,now

all: vpn-hack.so

vpn-hack.so: preload.o
	$(CCLD) $(CCLDFLAGS) -o $@ $^ -ldl

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< -Wall

clean:
	rm -f *.o vpn-hack.so

.PHONY: all clean
