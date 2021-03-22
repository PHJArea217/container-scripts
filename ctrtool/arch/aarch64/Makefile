all: arch.a

arch.a: syscall.o
	aarch64-linux-gnu-ar r $@ $<

syscall.o: syscall.S
	aarch64-linux-gnu-as -o $@ $<

clean:
	rm -f syscall.o arch.a

.PHONY: all clean
