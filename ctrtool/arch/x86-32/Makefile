all: arch.a

arch.a: syscall.o
	ar r $@ $<

syscall.o: syscall.S
	as --32 -march=i686 -o $@ $<

clean:
	rm -f syscall.o

.PHONY: all clean
