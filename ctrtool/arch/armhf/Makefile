all: arch.a

arch.a: syscall.o
	ar r $@ $<

syscall.o: syscall.S
	arm-linux-gnueabihf-as -o $@ $<

clean:
	rm -f syscall.o arch.a

.PHONY: all clean
