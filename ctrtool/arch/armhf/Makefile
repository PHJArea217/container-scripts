all: arch.a

arch.a: syscall.o
	arm-linux-gnueabihf-ar r $@ $<

syscall.o: syscall.S
	arm-linux-gnueabihf-as -mthumb -o $@ $<

clean:
	rm -f syscall.o arch.a

.PHONY: all clean
