all: arch.a

arch.a: syscall.o
	ar r $@ $<

syscall.o: syscall.S
	as -o $@ $<

clean:
	rm -f syscall.o arch.a

.PHONY: all clean
