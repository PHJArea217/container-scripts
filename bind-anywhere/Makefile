CC ?= gcc
CCLD ?= $(CC)
AR ?= ar
CFLAGS ?= -O3 -g -fvisibility=hidden -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2 -fPIC
CCLDFLAGS ?= -shared -Wl,-z,relro,-z,now

all: bind-anywhere.so

bind-anywhere.so: preload.o config.o
	$(CCLD) $(CCLDFLAGS) -o $@ $^ -ldl

%.o: %.c config.h
	$(CC) $(CFLAGS) -c -o $@ $< -Wall

clean:
	rm -f *.o bind-anywhere.so

.PHONY: all clean
