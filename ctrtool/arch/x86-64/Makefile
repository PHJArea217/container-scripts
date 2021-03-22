all: arch.a

arch.a: syscall.o
	x86_64-linux-gnu-ar r $@ $<

syscall.o: syscall.S
	x86_64-linux-gnu-as --64 -o $@ $<

clean:
	rm -f syscall.o arch.a

.PHONY: all clean
