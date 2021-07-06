CROSS_COMPILE ?= x86_64-linux-gnu-
AR := $(CROSS_COMPILE)ar
AS := $(CROSS_COMPILE)as
all: arch.a

arch.a: syscall.o
	$(AR) r $@ $<

syscall.o: syscall.S
	$(AS) --64 -o $@ $<

clean:
	rm -f syscall.o arch.a

.PHONY: all clean
