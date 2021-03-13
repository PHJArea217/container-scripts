all: arch.a

arch.a: syscall.o
	ar r $@ $<

syscall.o: syscall.c
	gcc -O3 -c -o $@ $<

clean:
	rm -f syscall.o arch.a

.PHONY: all clean
